#ifdef WIN32
#define RING3
#endif

#ifdef RING3
#include <windows.h>
#else
#include <windef.h>
#endif

#include "inlinehook.h"
#include"LDasm.h"


#ifdef RING3
#define __malloc(_s)	VirtualAlloc(NULL, _s, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
#define __free(_p)		VirtualFree(_p, 0, MEM_RELEASE)
#define JMP_SIZE		5
#else
#define __malloc(_s)	ExAllocatePool(NonPagedPool, _s)
#define __free(_p)		ExFreePool(_p)
#define JMP_SIZE		7
#endif

#ifdef RING3

BOOL
WriteReadOnlyMemory(
	LPBYTE	lpDest,
	LPBYTE	lpSource,
	ULONG	Length
	)
{
	BOOL bRet;
	DWORD dwOldProtect;
	bRet = FALSE;

	if (!VirtualProtect(lpDest, Length, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		return bRet;
	}

	memcpy(lpDest, lpSource, Length);

	bRet = VirtualProtect(lpDest, Length, dwOldProtect, &dwOldProtect);

	return	bRet;
}

#else

NTSTATUS
WriteReadOnlyMemory(
	LPBYTE	lpDest,
	LPBYTE	lpSource,
	ULONG	Length
	)
{
	NTSTATUS status;
	KSPIN_LOCK spinLock;
	KIRQL oldIrql;
	PMDL pMdlMemory;
	LPBYTE lpWritableAddress;

	status = STATUS_UNSUCCESSFUL;

	pMdlMemory = IoAllocateMdl(lpDest, Length, FALSE, FALSE, NULL);

	if (NULL == pMdlMemory)
		return status;

	MmBuildMdlForNonPagedPool(pMdlMemory);
    MmProbeAndLockPages(pMdlMemory, KernelMode, IoWriteAccess);
	lpWritableAddress = MmMapLockedPages(pMdlMemory, KernelMode);
    if (NULL != lpWritableAddress)
	{
		oldIrql	= 0;
		KeInitializeSpinLock(&spinLock);
		KeAcquireSpinLock(&spinLock, &oldIrql);

		memcpy(lpWritableAddress, lpSource, Length);

		KeReleaseSpinLock(&spinLock, oldIrql);
		MmUnmapLockedPages(lpWritableAddress, pMdlMemory);

		status = STATUS_SUCCESS;
	}

	MmUnlockPages(pMdlMemory);
    IoFreeMdl(pMdlMemory);

	return status;
}

#endif

BOOL 
GetPatchSize2(
	IN	void *Proc,			/* 需要Hook的函数地址 */
	IN	DWORD dwNeedSize,	/* Hook函数头部占用的字节大小 */
	OUT LPDWORD lpPatchSize	/* 返回根据函数头分析需要修补的大小 */
	)
{
	DWORD Length;
	PUCHAR pOpcode;
	DWORD PatchSize = 0;

	if (!Proc || !lpPatchSize)
	{
		return FALSE;
	}

	do
	{
		Length = SizeOfCode(Proc, &pOpcode);
		if ((Length == 1) && (*pOpcode == 0xC3))
			break;
		if ((Length == 3) && (*pOpcode == 0xC2))
			break;
		Proc = (PVOID)((DWORD)Proc + Length);

		PatchSize += Length;
		if (PatchSize >= dwNeedSize)
		{
			break;
		}

	}while(Length);

	*lpPatchSize = PatchSize;

	return TRUE;
}

BOOL
InstallInlineHook(
	IN	void *OrgProc,		/* 需要Hook的函数地址 */
	IN	void *NewProc,		/* 代替被Hook函数的地址 */
	OUT	void **RealProc		/* 返回原始函数的入口地址 */
	)
{
	DWORD dwPatchSize;    // 得到需要patch的字节大小
	//DWORD dwOldProtect;
	LPVOID lpHookFunc;    // 分配的Hook函数的内存
	DWORD dwBytesNeed;    // 分配的Hook函数的大小
	LPBYTE lpPatchBuffer; // jmp 指令的临时缓冲区

	if (!OrgProc || !NewProc || !RealProc)
	{
		return FALSE;
	}
	// 得到需要patch的字节大小
	if (!GetPatchSize2(OrgProc, JMP_SIZE, &dwPatchSize))
	{
		return FALSE;
	}

	/*
	0x00000800					0x00000800		sizeof(DWORD)	// dwPatchSize
	JMP	/ FAR 0xAABBCCDD		E9 DDCCBBAA		JMP_SIZE
	...							...				dwPatchSize		// Backup instruction
	JMP	/ FAR 0xAABBCCDD		E9 DDCCBBAA		JMP_SIZE
	*/

	dwBytesNeed = sizeof(DWORD) + JMP_SIZE + dwPatchSize + JMP_SIZE;

	lpHookFunc = __malloc(dwBytesNeed);

	//备份dwPatchSize到lpHookFunc
	*(DWORD *)lpHookFunc = dwPatchSize;

	//跳过开头的4个字节
	lpHookFunc = (LPVOID)((DWORD)lpHookFunc + sizeof(DWORD));

	//开始backup函数开头的字
	memcpy((BYTE *)lpHookFunc + JMP_SIZE, OrgProc, dwPatchSize);

	lpPatchBuffer = (LPBYTE)__malloc(dwPatchSize);

	//NOP填充
	memset(lpPatchBuffer, 0x90, dwPatchSize);

#ifdef RING3
	//jmp到Hook
	*(BYTE *)lpHookFunc = 0xE9;
	*(DWORD*)((DWORD)lpHookFunc + 1) = (DWORD)NewProc - (DWORD)lpHookFunc - JMP_SIZE;

	//跳回原始
	*(BYTE *)((DWORD)lpHookFunc + 5 + dwPatchSize) = 0xE9;
	*(DWORD*)((DWORD)lpHookFunc + 5 + dwPatchSize + 1) = ((DWORD)OrgProc + dwPatchSize) - ((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize) - JMP_SIZE;


	//jmp 
	*(BYTE *)lpPatchBuffer = 0xE9;
	//注意计算长度的时候得用OrgProc
	*(DWORD*)(lpPatchBuffer + 1) = (DWORD)lpHookFunc - (DWORD)OrgProc - JMP_SIZE;

#else

	//jmp到Hook
	*(BYTE *)lpHookFunc = 0xEA;
	*(DWORD*)((DWORD)lpHookFunc + 1) = (DWORD)NewProc;
	*(WORD*)((DWORD)lpHookFunc + 5) = 0x08;

	//跳回原始
	*(BYTE *)((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize) = 0xEA;
	*(DWORD*)((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize + 1) = ((DWORD)OrgProc + dwPatchSize);
	*(WORD*)((DWORD)lpHookFunc + JMP_SIZE + dwPatchSize + 5) = 0x08;

	//jmp far
	*(BYTE *)lpPatchBuffer = 0xEA;
	
	//跳到lpHookFunc函数
	*(DWORD*)(lpPatchBuffer + 1) = (DWORD)lpHookFunc;
	*(WORD*)(lpPatchBuffer + 5) = 0x08;
#endif

	WriteReadOnlyMemory((LPBYTE)OrgProc, lpPatchBuffer, dwPatchSize);

	__free(lpPatchBuffer);

	*RealProc = (void *)((DWORD)lpHookFunc + JMP_SIZE);

	return TRUE;
}

void UnInlineHook(
	void *OrgProc,  /* 需要恢复Hook的函数地址 */
	void *RealProc  /* 原始函数的入口地址 */
	)
{
	DWORD dwPatchSize;
	//DWORD dwOldProtect;
	LPBYTE lpBuffer;

	//找到分配的空间
	lpBuffer = (LPBYTE)((DWORD)RealProc - (sizeof(DWORD) + JMP_SIZE));
	//得到dwPatchSize
	dwPatchSize = *(DWORD *)lpBuffer;

	WriteReadOnlyMemory((LPBYTE)OrgProc, (LPBYTE)RealProc, dwPatchSize);

	//释放分配的跳转函数的空间
	__free(lpBuffer);

	return;
}