#pragma once

#include<Windows.h>
#include<vector>
#include<Psapi.h>
#include "ntdll.h"
#include "libdasm.h"
#pragma comment(lib, "psapi.lib")
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
	class ScanHook
	{
	public:
		ScanHook();
		bool InitScan(DWORD Pid);
		void CloseScan();
		bool GetProcessHookInfo(PPROCESS_HOOK_INFO Entry);

	private:
		typedef struct _MODULE_INFO
		{
			DWORD  DllBase;
			DWORD SizeOfImage;
			WCHAR FullName[260];
			WCHAR BaseName[64];
			void *ScanBuffer;
			void *OrigBuffer;
		} MODULE_INFO;

		typedef struct _PE_INFO
		{
			PIMAGE_NT_HEADERS PeHead;
			PIMAGE_EXPORT_DIRECTORY ExportTable;
			DWORD ExportSize;
			PIMAGE_IMPORT_DESCRIPTOR ImportTable;
			DWORD ImportSize;
		} PE_INFO, *PPE_INFO;

	private:
		bool ScanInlineHook(char *ApiName, DWORD ApiAddress);
		bool ScanEatHook(MODULE_INFO ModuleInfo);
		bool ScanIatHook(MODULE_INFO ModuleInfo);

	private:
		bool IsRedirction, IsFromRedirction;
		HANDLE hProcess;
		DWORD MajorVersion, MinorVersion;
		DWORD *ApiSetMapHead;
		vector<MODULE_INFO> ModuleInfo;
		vector<MODULE_INFO>::iterator ModuleInfoiter;
		vector<PROCESS_HOOK_INFO> HookInfo;
		vector<PROCESS_HOOK_INFO>::iterator HookInfoiter;
		PROCESS_HOOK_INFO Info;
		bool ElevatedPriv();
		bool CollectSystemInfo();
		bool CollectModuleInfo();
		bool PeLoader(WCHAR *FilePath, void *BaseAddress, DWORD BufferSize, DWORD DllBase);
		void FixRelocTable(DWORD ModuleBase, DWORD NewModuleBase);
		bool ParsePe(DWORD ImageBase, PPE_INFO PeInfo);
		DWORD GetExportByOrdinal(DWORD ModuleBase, WORD Ordinal);
		DWORD GetExportByName(DWORD ModuleBase, char *ProcName);
		DWORD FileNameRedirection(DWORD ModuleBase, char *RedirectionName);
		bool ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size);
		DWORD MyGetProcAddress(char *DllName, char *ApiName, bool *IsApiSet, WCHAR *RealDllName);
		bool GetModuleInfomation(WCHAR *DllName, vector<MODULE_INFO>::iterator &iter);
		void GetModulePath(DWORD Address, WCHAR *ModulePath);
		void GetModulePathByAddress(DWORD Address, WCHAR *ModulePath);
	};
}