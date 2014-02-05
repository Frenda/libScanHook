#pragma once

#include<Windows.h>
#include<vector>
#include<Psapi.h>
#include "ntdll.h"
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
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
			BYTE *ScanBuffer;
			BYTE *OrigBuffer;
		} MODULE_INFO;

		typedef struct _PE_INFO
		{
			PIMAGE_NT_HEADERS PeHead;
			PIMAGE_EXPORT_DIRECTORY ExportTable;
			DWORD ExportSize;
			PIMAGE_IMPORT_DESCRIPTOR ImportTable;
			DWORD ImportSize;
		} PE_INFO, *PPE_INFO;

		typedef struct _API_SET_NAMESPACE_ENTRY_V2
		{
			DWORD NameOffset;
			DWORD NameLength;
			DWORD DataOffset;                     //指明API_SET_VALUE_ARRAY_V2相对于API_SET_NAMESPACE_ARRAY_V2的偏移
		} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

		typedef struct _API_SET_NAMESPACE_ARRAY_V2
		{
			DWORD Version;
			DWORD Count;       //指明有多少个API_SET_MAP_ENTRY
			API_SET_NAMESPACE_ENTRY_V2 Entry[1];
		} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

		typedef struct _API_SET_VALUE_ENTRY_V2
		{
			DWORD NameOffset;
			DWORD NameLength;
			DWORD ValueOffset;
			DWORD ValueLength;
		} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

		typedef struct _API_SET_VALUE_ARRAY_V2
		{
			DWORD Count;                                  //API_SET_VALUE_ENTRY_V2的数量
			API_SET_VALUE_ENTRY_V2 Entry[1];
		} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

		typedef struct _API_SET_NAMESPACE_ENTRY_V4
		{
			DWORD Flags;
			DWORD NameOffset;
			DWORD NameLength;
			DWORD AliasOffset;
			DWORD AliasLength;
			DWORD DataOffset;                                 //API_SET_VALUE_ARRAY_V4相对于API_SET_NAMESPACE_ARRAY_V4的偏移
		} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

		typedef struct _API_SET_NAMESPACE_ARRAY_V4
		{
			DWORD Version;
			DWORD Size;
			DWORD Flags;
			DWORD Count;                                         //指明有多少个API_SET_NAMESPACE_ENTRY_V4
			API_SET_NAMESPACE_ENTRY_V4 Entry[1];
		} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

		typedef struct _API_SET_VALUE_ENTRY_V4
		{
			DWORD Flags;
			DWORD NameOffset;
			DWORD NameLength;
			DWORD ValueOffset;
			DWORD ValueLength;
		} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

		typedef struct _API_SET_VALUE_ARRAY_V4
		{
			DWORD Flags;
			DWORD Count;
			API_SET_VALUE_ENTRY_V4 Entry[1];
		} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;

	private:
		bool ScanInlineHook(DWORD ApiAdress);
		bool ScanEatHook(MODULE_INFO ModuleInfo);
		bool ScanIatHook(MODULE_INFO ModuleInfo);

	private:
		bool IsRedirction, IsFromRedirction;
		HANDLE hProcess;
		DWORD MajorVersion, MinorVersion;
		DWORD *ApiSetMapHead;
		vector<MODULE_INFO> ModuleInfo;
		vector<MODULE_INFO>::iterator Moduleiter;
		vector<PROCESS_HOOK_INFO> HookInfo;
		vector<PROCESS_HOOK_INFO>::iterator Infoiter;
		PROCESS_HOOK_INFO Info;
		bool ElevatedPriv();
		void GetWindowsVersion();
		PDWORD  GetApiSetMapHead();
		bool CollectModuleInfo();
		bool PeLoader(WCHAR *FilePath, void *BaseAddress, DWORD BufferSize);
		void FixRelocTable(DWORD hModule, DWORD BaseAddress);
		bool ParsePe(DWORD ImageBase, PPE_INFO PeInfo);
		DWORD GetExportByName(HMODULE hModule, char *ProcName);
		DWORD FileNameRedirection(HMODULE hModule, char *RedirectionName);
		bool ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size);
		DWORD GetRealApiAddress(char *DllName, char *ApiName, bool *IsApiSet, WCHAR *RealDllName);
		DWORD GetModulePathByAddress(HANDLE hProcess, DWORD Address, WCHAR *ModulePath);
	};
}