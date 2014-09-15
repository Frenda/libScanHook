#pragma once

#include<Windows.h>
#include<vector>
#include "ntdll.h"
#include "libdasm.h"
using std::vector;

typedef enum _HOOK_TYPE
{
	EatHook,
	IatHook,
	InlineHook
} HOOK_TYPE;

typedef struct _PROCESS_HOOK_INFO
{
	DWORD HookType;
	DWORD OriginalAddress;                   //原函数地址
	DWORD HookAddress;                       //钩子的地址
	WCHAR HookedApiName[128];         //被挂钩的函数名
	WCHAR HookedModule[64];            //被挂钩的模块名
	WCHAR HookLocation[260];            //钩子所在的模块
} PROCESS_HOOK_INFO, *PPROCESS_HOOK_INFO;

namespace libScanHook
{
	class SCANHOOK
	{
	public:
		SCANHOOK();
		~SCANHOOK();
		bool InitScan(DWORD Pid);
		//void CloseScan();
		bool GetProcessHookInfo(PPROCESS_HOOK_INFO Entry);

	private:
		typedef struct _MODULE_INFO
		{
			DWORD  DllBase;
			DWORD SizeOfImage;
			WCHAR FullName[260];
			WCHAR BaseName[64];
			void *MemoryImage;
			void *DiskImage;
		} MODULE_INFO;

		typedef struct _PE_INFO
		{
			PIMAGE_NT_HEADERS PeHead;
			DWORD ExportTableRva;
			DWORD ExportSize;
			DWORD ImportTableRva;
			DWORD ImportSize;
		} PE_INFO, *PPE_INFO;

	private:
		bool ScanInlineHook(char *ApiName, DWORD Address);
		bool ScanEatHook();
		bool ScanIatHook();
		void AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, WCHAR *HookedModule);
		void AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, char *HookedModule);

	private:
		bool m_IsFromIat, m_IsFromEat;
		HANDLE m_hProcess;
		DWORD m_MajorVersion, m_MinorVersion;
		DWORD *m_ApiSetMapHead;
		vector<MODULE_INFO> ModuleInfo;
		vector<MODULE_INFO>::iterator ModuleInfoiter;
		vector<PROCESS_HOOK_INFO> HookInfo;
		vector<PROCESS_HOOK_INFO>::iterator HookInfoiter;
		bool ElevatedPriv();
		bool QuerySystemInfo();
		bool QueryModuleInfo();
		bool ReadMemoryImage();
		void FreeMemoryImage();
		bool PeLoader(WCHAR *FilePath, DWORD DllBase, void *Buffer, DWORD BufferSize);
		bool FixBaseRelocTable(DWORD NewImageBase, DWORD ExistImageBase);
		PIMAGE_BASE_RELOCATION ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff);
		bool IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva);
		bool ParsePe(DWORD ImageBase, PPE_INFO PeInfo);
		UINT AlignSize(UINT Size, UINT Align);
		DWORD GetExportByOrdinal(DWORD ImageBase, WORD Ordinal);
		DWORD GetExportByName(DWORD ImageBase, char *ProcName);
		DWORD FileNameRedirection(char *RedirectionName);
		bool ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size);
		DWORD MyGetProcAddress(char *DllName, char *ApiName, bool *IsApiSet, WCHAR *RealDllName);
		bool GetModuleInfomation(WCHAR *DllName, vector<MODULE_INFO>::iterator &iter);
		bool GetModuleInfomation(DWORD Address, vector<MODULE_INFO>::iterator &iter);
		void GetModulePath(DWORD Address, WCHAR *ModulePath);
		void GetModulePathByAddress(DWORD Address, WCHAR *ModulePath);
		DWORD FindDosHeadInMemory(DWORD Address);
	};
}