#include "libScanHook.h"

namespace libscanhook
{
	SCANHOOK::SCANHOOK()
	{
		m_IsFromIat = 0;
		m_IsFromEat = 0;
		ElevatedPriv();
	}

	SCANHOOK::~SCANHOOK()
	{
		for (ModuleInfoiter = ModuleInfo.begin(); ModuleInfoiter != ModuleInfo.end(); ++ModuleInfoiter)
		{
			if (ModuleInfoiter->DiskImage)
				delete[] ModuleInfoiter->DiskImage;
		}
		ModuleInfo.clear();
		HookInfo.clear();
	}

	bool SCANHOOK::InitScan(DWORD Pid)
	{
		bool ret = 0;
		if (QuerySystemInfo())
		{
			m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
			if (m_hProcess)
			{
				if (QueryModuleInfo())
				{
					for (ModuleInfoiter = ModuleInfo.begin(); ModuleInfoiter != ModuleInfo.end(); ++ModuleInfoiter)
					{
						if (ReadMemoryImage())
						{
							ScanEatHook();
							ScanIatHook();
						}
						FreeMemoryImage();
					}
					ret = 1;
					HookInfoiter = HookInfo.begin();
				}
				CloseHandle(m_hProcess);
			}
		}
		return ret;
	}

	bool SCANHOOK::GetProcessHookInfo(PPROCESS_HOOK_INFO Entry)
	{
		bool ret = 0;
		if (HookInfoiter != HookInfo.end())
		{
			Entry->HookType = HookInfoiter->HookType;
			Entry->OriginalAddress = HookInfoiter->OriginalAddress;
			Entry->HookAddress = HookInfoiter->HookAddress;
			wcscpy_s(Entry->HookedApiName, 128, HookInfoiter->HookedApiName);
			wcscpy_s(Entry->HookedModule, 64, HookInfoiter->HookedModule);
			wcscpy_s(Entry->HookLocation, 260, HookInfoiter->HookLocation);
			++HookInfoiter;
			ret = 1;
		}
		return ret;
	}

	bool SCANHOOK::ScanInlineHook(char *ApiName, DWORD Address)
	{
		bool ret = 0, IsHook = 0;
		DWORD Dest, Src, Index, InstrLen, HookAddress = 0;
		vector<MODULE_INFO>::iterator iter;
		INSTRUCTION Instr, Instr2;
		if (GetModuleInfomation(Address, iter))
		{
			//函数的地址 - 函数所在的DLL的基址 + DLL重载后的地址 = 函数在重载后的DLL中的地址
			Dest = Address - iter->DllBase + (DWORD)iter->MemoryImage;
			Src = Address - iter->DllBase + (DWORD)iter->DiskImage;
			for (Index = 0; Index < 15; ++Index)
			{
				if ((*(BYTE *)(Dest + Index)) != (*(BYTE *)(Src + Index)))
				{
					InstrLen = get_instruction(&Instr, ((BYTE *)(Dest + Index)), MODE_32);
					switch (Instr.type)
					{
					case INSTRUCTION_TYPE_JMP:
					{
						if (Instr.opcode == 0xFF && Instr.modrm == 0x25)
							HookAddress = Instr.op1.displacement;
						if (Instr.opcode == 0xEB || Instr.opcode == 0xE9)
							HookAddress = Address + Instr.op1.immediate + InstrLen;
						IsHook = 1;
						break;
					}
					case INSTRUCTION_TYPE_PUSH:
					{
						InstrLen = get_instruction(&Instr2, (BYTE *)(Dest + Index + InstrLen), MODE_32);
						if (Instr2.type == INSTRUCTION_TYPE_RET)
						{
							HookAddress = Instr.op1.displacement;
							IsHook = 1;
						}
						break;
					}
					case INSTRUCTION_TYPE_MOV:
					{
						InstrLen = get_instruction(&Instr2, (BYTE *)(Dest + Index + InstrLen), MODE_32);
						if (Instr2.type == INSTRUCTION_TYPE_JMP)
						{
							HookAddress = Address + Instr.op1.displacement;
							IsHook = 1;
						}
						break;
					}
					case INSTRUCTION_TYPE_CALL:
					{
						if (Instr.opcode == 0xFF && Instr.modrm == 0x15)
							HookAddress = Instr.op1.displacement;
						if (Instr.opcode == 0xEB || Instr.opcode == 0x9A)
							HookAddress = Address + Instr.op1.immediate + InstrLen;
						IsHook = 1;
						break;
					}
					default:
						break;
					}
					break;
				}
			}
			if (IsHook)
				AddHookInfoToList(InlineHook, Address, HookAddress, ApiName, ModuleInfoiter->BaseName);
		}
		return ret;
	}


	bool SCANHOOK::ScanEatHook()
	{
		bool ret = 0;
		char *ApiName;
		WORD *NameOrd;
		DWORD tem, tem1;
		DWORD i, ApiAddress, OriApiAddress, Tem;
		DWORD *Ent, *Eat, *OriEat;
		LIBPE Pe;
		PE_INFO PeInfo, OrigPeInfo;
		vector<MODULE_INFO>::iterator iter;
		PIMAGE_EXPORT_DIRECTORY ExporTable, OrigExportTable;
		if (Pe.Parse((DWORD)ModuleInfoiter->MemoryImage, &PeInfo) && Pe.Parse((DWORD)ModuleInfoiter->DiskImage, &OrigPeInfo))
		{
			if (PeInfo.ExportSize)
			{
				ExporTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)ModuleInfoiter->MemoryImage + PeInfo.ExportTableRva);
				OrigExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)ModuleInfoiter->DiskImage + PeInfo.ExportTableRva);
				Eat = (DWORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfFunctions);
				Ent = (DWORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfNames);
				NameOrd = (WORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfNameOrdinals);
				OriEat = (DWORD *)((DWORD)ModuleInfoiter->DiskImage + OrigExportTable->AddressOfFunctions);
				for (i = 0; i < ExporTable->NumberOfNames; ++i)
				{
					if (Pe.IsGlobalVar(OrigPeInfo.PeHead, OriEat[NameOrd[i]]))
						continue;
					tem = Eat[NameOrd[i]];
					tem1 = OriEat[NameOrd[i]];
					ApiName = (char *)(Ent[i] + (DWORD)ModuleInfoiter->DiskImage);
					ApiAddress = Eat[NameOrd[i]] + ModuleInfoiter->DllBase;
					OriApiAddress = OriEat[NameOrd[i]] + ModuleInfoiter->DllBase;
					Tem = OriEat[NameOrd[i]] + (DWORD)ModuleInfoiter->DiskImage;
					if (Tem >= (DWORD)OrigExportTable && Tem < ((DWORD)OrigExportTable + PeInfo.ExportSize))
						OriApiAddress = FileNameRedirection((char *)Tem);
					else
						ScanInlineHook(ApiName, OriApiAddress);
					if ((Eat[NameOrd[i]] != OriEat[NameOrd[i]]) && (OriApiAddress != ApiAddress))
						AddHookInfoToList(EatHook, OriApiAddress, ApiAddress, ApiName, ModuleInfoiter->BaseName);
				}
				ret = 1;
			}
		}
		return ret;
	}

	bool SCANHOOK::ScanIatHook()
	{
		bool ret = 0, IsApiSet;
		char *DllName, *ApiName;
		char OrdinalName[13];
		WCHAR RealDllName[64];
		WORD Ordinal;
		DWORD ApiAddress, OriApiAddress;
		PIMAGE_THUNK_DATA FirstThunk, OriThunk;
		PIMAGE_IMPORT_BY_NAME ByName;
		LIBPE Pe;
		PE_INFO PeInfo;
		PIMAGE_IMPORT_DESCRIPTOR ImportTable;
		if (Pe.Parse((DWORD)ModuleInfoiter->MemoryImage, &PeInfo))
		{
			if (PeInfo.ImportSize)
			{
				ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)ModuleInfoiter->MemoryImage + PeInfo.ImportTableRva);
				while (ImportTable->FirstThunk)
				{
					if (ImportTable->OriginalFirstThunk)
					{
						DllName = (char *)(ImportTable->Name + (DWORD)ModuleInfoiter->MemoryImage);
						OriThunk = (PIMAGE_THUNK_DATA)(ImportTable->OriginalFirstThunk + (DWORD)ModuleInfoiter->MemoryImage);
						FirstThunk = (PIMAGE_THUNK_DATA)(ImportTable->FirstThunk + (DWORD)ModuleInfoiter->MemoryImage);
						while (FirstThunk->u1.Function)
						{
							ApiAddress = FirstThunk->u1.Function;
							if (OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							{
								Ordinal = OriThunk->u1.Ordinal & 0x0000FFFF;
								OriApiAddress = MyGetProcAddress(DllName, (char *)Ordinal, &IsApiSet, RealDllName);
								sprintf_s(OrdinalName, 13, "Ordinal:%04x", Ordinal);
								ApiName = OrdinalName;
							}
							else
							{
								ByName = (PIMAGE_IMPORT_BY_NAME)(OriThunk->u1.AddressOfData + (DWORD)ModuleInfoiter->MemoryImage);
								ApiName = ByName->Name;
								OriApiAddress = MyGetProcAddress(DllName, ApiName, &IsApiSet, RealDllName);
							}
							if (OriApiAddress && (ApiAddress != OriApiAddress))
							{
								if (IsApiSet)
									AddHookInfoToList(IatHook, OriApiAddress, ApiAddress, ApiName, RealDllName);
								else
									AddHookInfoToList(IatHook, OriApiAddress, ApiAddress, ApiName, DllName);
							}
							++OriThunk;
							++FirstThunk;
						}
					}
					++ImportTable;
				}
			}
		}
		return ret;
	}

	void SCANHOOK::AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, WCHAR *HookedModule)
	{
		PROCESS_HOOK_INFO Info;
		memset(&Info, 0, sizeof(PROCESS_HOOK_INFO));
		__try
		{
			Info.HookType = HookType;
			Info.OriginalAddress = OriginalAddress;
			Info.HookAddress = HookAddress;
			MultiByteToWideChar(CP_ACP, 0, HookedApiName, strlen(HookedApiName) + 1, Info.HookedApiName, 128);
			wcscpy_s(Info.HookedModule, 64, HookedModule);
			GetModulePathByAddress(HookAddress, Info.HookLocation);
			HookInfo.push_back(Info);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}

	void SCANHOOK::AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, char *HookedModule)
	{
		WCHAR NameBuffer[64];
		__try
		{
			MultiByteToWideChar(CP_ACP, 0, HookedModule, strlen(HookedModule) + 1, NameBuffer, 64);
			AddHookInfoToList(HookType, OriginalAddress, HookAddress, HookedApiName, NameBuffer);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}

	bool  SCANHOOK::ElevatedPriv()
	{
		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
			return 0;
		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
			return 0;
		CloseHandle(hToken);
		return 1;
	}

	bool SCANHOOK::QuerySystemInfo()
	{
		bool ret = 0;
		PNT_PEB Peb;
		NT_PROCESS_BASIC_INFORMATION BaseInfo;
		if (!NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &BaseInfo, sizeof(NT_PROCESS_BASIC_INFORMATION), 0))
		{
			Peb = (PNT_PEB)(BaseInfo.PebBaseAddress);
			m_MajorVersion = Peb->OSMajorVersion;
			m_MinorVersion = Peb->OSMinorVersion;
			if (m_MajorVersion >= 6 && m_MinorVersion >= 1)
				m_ApiSetMapHead = (DWORD *)(Peb->ApiSetMap);
			ret = 1;
		}
		return ret;
	}

	bool SCANHOOK::QueryModuleInfo()
	{
		bool ret = 0;
		PELOADER Ldr;
		HANDLE hSnap;
		MODULEENTRY32 me32;
		MODULE_INFO Info;
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(m_hProcess));
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			me32.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(hSnap, &me32))
			{
				do
				{
					Info.DllBase = (DWORD)me32.modBaseAddr;
					Info.SizeOfImage = me32.modBaseSize;
					wcscpy_s(Info.BaseName, 64, me32.szModule);
					wcscpy_s(Info.FullName, 260, me32.szExePath);
					Info.DiskImage = new BYTE[Info.SizeOfImage];
					Ldr.Loader(Info.FullName, (DWORD)Info.DllBase, Info.DiskImage, Info.SizeOfImage);
					ModuleInfo.push_back(Info);
				} while (Module32Next(hSnap, &me32));
				ret = 1;
			}
			CloseHandle(hSnap);
		}
		return ret;
	}

	bool SCANHOOK::ReadMemoryImage()
	{
		bool ret = 0;
		ModuleInfoiter->MemoryImage = new BYTE[ModuleInfoiter->SizeOfImage];
		if (ModuleInfoiter->MemoryImage)
		{
			if (ReadProcessMemory(m_hProcess, (void *)ModuleInfoiter->DllBase, ModuleInfoiter->MemoryImage, ModuleInfoiter->SizeOfImage, 0))
				ret = 1;
		}
		return ret;
	}

	void SCANHOOK::FreeMemoryImage()
	{
		if (ModuleInfoiter->MemoryImage)
		{
			delete[] ModuleInfoiter->MemoryImage;
			ModuleInfoiter->MemoryImage = 0;
		}
	}

	DWORD SCANHOOK::GetExportByOrdinal(DWORD ImageBase, WORD Ordinal)
	{
		DWORD ApiAddress = 0;
		DWORD *Eat;
		LIBPE Pe;
		PE_INFO PeInfo;
		PIMAGE_EXPORT_DIRECTORY ExportTable;
		Pe.Parse(ImageBase, &PeInfo);
		if (PeInfo.ExportSize)
		{
			ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + PeInfo.ExportTableRva);
			Eat = (DWORD *)(ImageBase + ExportTable->AddressOfFunctions);
			ApiAddress = ((Eat[Ordinal - ExportTable->Base] != 0) ? (ImageBase + Eat[Ordinal - ExportTable->Base]) : 0);
			if ((ApiAddress >= (DWORD)ExportTable) && (ApiAddress < ((DWORD)ExportTable + PeInfo.ExportSize)))
			{
				ApiAddress = FileNameRedirection((char *)ApiAddress);
				m_IsFromIat = 1;
			}
		}
		return ApiAddress;
	}

	DWORD SCANHOOK::GetExportByName(DWORD ImageBase, char *ProcName)
	{
		int cmp;
		char *ApiName;
		DWORD ApiAddress = 0;
		WORD Ordinal, *NameOrd;
		DWORD *Ent, *Eat, HigthIndex, LowIndex = 0, MidIndex;
		LIBPE Pe;
		PE_INFO PeInfo;
		PIMAGE_EXPORT_DIRECTORY ExportTable;
		Pe.Parse(ImageBase, &PeInfo);
		if (PeInfo.ExportSize)
		{
			ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + PeInfo.ExportTableRva);
			Eat = (DWORD *)(ImageBase + ExportTable->AddressOfFunctions);
			Ent = (DWORD *)(ImageBase + ExportTable->AddressOfNames);
			NameOrd = (WORD *)(ImageBase + ExportTable->AddressOfNameOrdinals);
			HigthIndex = ExportTable->NumberOfNames;
			__try
			{
				while (LowIndex <= HigthIndex)
				{
					MidIndex = (LowIndex + HigthIndex) / 2;
					ApiName = (char *)(ImageBase + Ent[MidIndex]);
					cmp = strcmp(ProcName, ApiName);
					if (cmp < 0)
					{
						HigthIndex = MidIndex - 1;
						continue;
					}
					if (cmp > 0)
					{
						LowIndex = MidIndex + 1;
						continue;
					}
					if (cmp == 0)
					{
						Ordinal = NameOrd[MidIndex];
						break;
					}
				}
				if (LowIndex > HigthIndex)
					return 0;
				ApiAddress = (ImageBase + Eat[Ordinal]);
				if (ApiAddress >= (DWORD)ExportTable && (ApiAddress < ((DWORD)ExportTable + PeInfo.ExportSize)))
				{
					ApiAddress = FileNameRedirection((char *)ApiAddress);
					m_IsFromIat = 1;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return 0;
			}
		}
		return ApiAddress;
	}

	DWORD SCANHOOK::FileNameRedirection(char *RedirectionName)
	{
		char *ptr, *ProcName;
		char Buffer[128];
		WORD Oridnal;
		WCHAR DllName[128];
		DWORD ApiAddress = 0;
		vector<MODULE_INFO>::iterator iter;
		strcpy_s(Buffer, 128, RedirectionName);
		ptr = strchr(Buffer, '.');
		if (ptr)
		{
			*ptr = 0;
			MultiByteToWideChar(CP_ACP, 0, Buffer, sizeof(Buffer), DllName, 128);
			if (!_wcsnicmp(DllName, L"api-", 4))
			{
				m_IsFromEat = 1;
				ResolveApiSet(DllName, DllName, 128);
				m_IsFromEat = 0;
				goto get_api_address;
			}
			else
			{
			get_api_address:
				if (GetModuleInfomation(DllName, iter))
				{
					if (*(char *)(ptr + 1) == '#')
					{
						Oridnal = (WORD)strtoul((char *)(ptr + 2), 0, 10);
						ApiAddress = GetExportByOrdinal((DWORD)iter->DiskImage, Oridnal);
					}
					else
					{
						ProcName = (char *)(ptr + 1);
						ApiAddress = GetExportByName((DWORD)iter->DiskImage, ProcName);
					}
					if (ApiAddress)
						ApiAddress = ApiAddress - (DWORD)iter->DiskImage + iter->DllBase;
				}
			}
		}
		return ApiAddress;
	}

	bool SCANHOOK::ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size)
	{
		bool ret = 0;
		WCHAR *NameBuffer, *ptr;
		WCHAR LibName[64];
		DWORD LibNameSize, HostNameSize;
		DWORD *Version;;
		PNT_API_SET_NAMESPACE_ARRAY_V2 SetMapHead_v2;
		PNT_API_SET_VALUE_ARRAY_V2 SetMapHost_v2;
		PNT_API_SET_NAMESPACE_ARRAY_V4 SetMapHead_v4;
		PNT_API_SET_VALUE_ARRAY_V4 SetMapHost_v4;
		Version = m_ApiSetMapHead;
		ptr = wcschr(ApiSetName, L'.');
		if (ptr)
			*ptr = 0;
		if (Version)
		{
			switch (*Version)
			{
			case 2:
			{
					  SetMapHead_v2 = (PNT_API_SET_NAMESPACE_ARRAY_V2)Version;
					  for (DWORD i = 0; i < SetMapHead_v2->Count; i++)
					  {
						  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHead_v2->Entry[i].NameOffset);
						  LibNameSize = SetMapHead_v2->Entry[i].NameLength;
						  wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
						  if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
						  {
							  SetMapHost_v2 = (PNT_API_SET_VALUE_ARRAY_V2)((DWORD)SetMapHead_v2 + SetMapHead_v2->Entry[i].DataOffset);
							  if (SetMapHost_v2->Count == 1)
							  {
								  HostNameSize = SetMapHost_v2->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[0].ValueOffset);
							  }
							  else
							  {
								  HostNameSize = SetMapHost_v2->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[0].ValueOffset);
								  if (!_wcsnicmp(ModuleInfoiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || m_IsFromEat)
								  {
									  HostNameSize = SetMapHost_v2->Entry[1].ValueLength;
									  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[1].ValueOffset);
								  }								  
							  }
							  wcsncpy_s(HostName, Size, NameBuffer, HostNameSize / sizeof(WCHAR));
							  ret = 1;
							  break;
						  }
					  }
			}
			case 4:
			{
					  SetMapHead_v4 = (PNT_API_SET_NAMESPACE_ARRAY_V4)Version;
					  for (DWORD i = 0; i < SetMapHead_v4->Count; i++)
					  {
						  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHead_v4->Entry[i].NameOffset);
						  LibNameSize = SetMapHead_v4->Entry[i].NameLength;
						  wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
						  if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
						  {
							  SetMapHost_v4 = (PNT_API_SET_VALUE_ARRAY_V4)((DWORD)SetMapHead_v4 + SetMapHead_v4->Entry[i].DataOffset);
							  if (SetMapHost_v4->Count == 1)
							  {
								  HostNameSize = SetMapHost_v4->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[0].ValueOffset);
							  }
							  else
							  {
								  HostNameSize = SetMapHost_v4->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[0].ValueOffset);
								  if (!_wcsnicmp(ModuleInfoiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || m_IsFromEat)
								  {
									  HostNameSize = SetMapHost_v4->Entry[1].ValueLength;
									  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[1].ValueOffset);
								  }								  
							  }
							  wcsncpy_s(HostName, Size, NameBuffer, HostNameSize / sizeof(WCHAR));
							  ret = 1;
							  break;
						  }
					  }
			}
			default:
				break;
			}
		}
		return ret;
	}

	DWORD SCANHOOK::MyGetProcAddress(char *DllName, char *ApiName, bool *IsApiSet, WCHAR *RealDllName)
	{
		DWORD ApiAddress = 0;
		WCHAR NameBuffer[64], HostName[64];
		vector<MODULE_INFO>::iterator iter;
		*IsApiSet = 0;
		MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, NameBuffer, 64);
		if (HIWORD((DWORD)ApiName))
		{
			if (GetModuleInfomation(NameBuffer, iter))
			{
				ApiAddress = GetExportByName((DWORD)iter->DiskImage, ApiName);
				if (ApiAddress && !m_IsFromIat)
					ApiAddress = ApiAddress - (DWORD)iter->DiskImage + iter->DllBase;
				m_IsFromIat = 0;
			}
			else
			{
				if (!_wcsnicmp(NameBuffer, L"api-", 4) && (m_MajorVersion >= 6 && m_MinorVersion >= 1))
				{
					if (ResolveApiSet(NameBuffer, HostName, 64))
					{
						*IsApiSet = 1;
						wcscpy_s(RealDllName, 64, HostName);
						if (GetModuleInfomation(HostName, iter))
						{
							ApiAddress = GetExportByName((DWORD)iter->DiskImage, ApiName);
							if (ApiAddress && !m_IsFromIat)
								ApiAddress = ApiAddress - (DWORD)iter->DiskImage + iter->DllBase;
							m_IsFromIat = 0;
						}
					}
				}
			}
		}
		else
		{
			if (GetModuleInfomation(NameBuffer, iter))
			{
				ApiAddress = GetExportByOrdinal((DWORD)iter->DiskImage, (WORD)ApiName);
				if (ApiAddress && !m_IsFromIat)
					ApiAddress = ApiAddress - (DWORD)iter->DiskImage + iter->DllBase;
				m_IsFromIat = 0;
			}
		}
		return ApiAddress;
	}

	bool SCANHOOK::GetModuleInfomation(WCHAR *DllName, vector<MODULE_INFO>::iterator &iter)
	{
		bool ret = 0;
		size_t Len;
		Len = wcslen(DllName);
		for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); ++iter)
		{
			if (!_wcsnicmp(iter->BaseName, DllName, Len))
			{
				ret = 1;
				break;
			}
		}
		return ret;
	}

	bool SCANHOOK::GetModuleInfomation(DWORD Address, vector<MODULE_INFO>::iterator &iter)
	{
		bool ret = 0;
		Address = FindDosHeadInMemory(Address);
		if (Address)
		{
			for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); ++iter)
			{
				if (Address == iter->DllBase)
				{
					ret = 1;
					break;
				}
			}
		}
		return ret;
	}

	void SCANHOOK::GetModulePath(DWORD Address, WCHAR *ModulePath)
	{
		vector<MODULE_INFO>::iterator iter;
		for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); ++iter)
		{
			if (iter->DllBase == Address)
				wcscpy_s(ModulePath, 260, iter->FullName);
		}
	}

	void SCANHOOK::GetModulePathByAddress(DWORD Address, WCHAR *ModulePath)
	{
		Address = FindDosHeadInMemory(Address);
		if (Address)
			GetModulePath(Address, ModulePath);
	}

	DWORD SCANHOOK::FindDosHeadInMemory(DWORD Address)
	{
		DWORD Buffer, Tem;
		Tem = Address;
		if (Address)
		{
			Tem &= 0xFFFF0000;
			__try
			{
				while (Tem)
				{
					if (ReadProcessMemory(m_hProcess, (void *)Tem, &Buffer, sizeof(void *), 0))
					{
						if ((WORD)Buffer == IMAGE_DOS_SIGNATURE)
						{
							if (ReadProcessMemory(m_hProcess, (void *)(Tem + 0x3C), &Buffer, sizeof(void *), 0))
							{
								if (ReadProcessMemory(m_hProcess, (void *)(Buffer + Tem), &Buffer, sizeof(void *), 0))
								{
									if (Buffer == IMAGE_NT_SIGNATURE)
									{
										Address = Tem;
										break;
									}
								}
							}
						}
					}
					Tem -= 0x10000;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				Address = 0;
			}
		}
		return Address;
	}
}