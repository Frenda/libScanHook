#include "libScanHook.h"

namespace libScanHook
{
	ScanHook::ScanHook()
	{
		IsRedirction = 0;
		IsFromRedirction = 0;
		ElevatedPriv();
		GetWindowsVersion();
		ApiSetMapHead = GetApiSetMapHead();
	}

	bool ScanHook::InitScan(DWORD Pid)
	{
		bool ret = 0;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
		if (hProcess)
		{
			if (CollectModuleInfo())
			{
				for (Moduleiter = ModuleInfo.begin(); Moduleiter != ModuleInfo.end(); Moduleiter++)
				{
					ScanEatHook(*Moduleiter);
					ScanIatHook(*Moduleiter);
				}
				ret = 1;
				Infoiter = HookInfo.begin();
			}
			CloseHandle(hProcess);
		}
		return ret;
	}

	void ScanHook::CloseScan()
	{
		vector<MODULE_INFO>::iterator iter;
		for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); iter++)
		{
			if (iter->ScanBuffer)
				delete[] iter->ScanBuffer;
			if (iter->OrigBuffer)
				delete[] iter->OrigBuffer;
		}
	}

	bool ScanHook::GetProcessHookInfo(PPROCESS_HOOK_INFO Entry)
	{
		bool ret = 0;
		if (Infoiter != HookInfo.end())
		{
			Entry->HookType = Infoiter->HookType;
			Entry->OriginalAddress = Infoiter->OriginalAddress;
			Entry->HookAddress = Infoiter->HookAddress;
			memset(Entry->HookedApiName, 0, 64 * sizeof(WCHAR ));
			wcscpy_s(Entry->HookedApiName, 64, Infoiter->HookedApiName);
			memset(Entry->HookedModule, 0, 64 * sizeof(WCHAR));
			wcscpy_s(Entry->HookedModule, 64, Infoiter->HookedModule);
			memset(Entry->HookLocation, 0, 260 * sizeof(WCHAR));
			wcscpy_s(Entry->HookLocation, 260, Infoiter->HookLocation);
			Infoiter++;
			ret = 1;
		}
		return ret;
	}

	bool ScanHook::ScanEatHook(MODULE_INFO ModuleInfo)
	{
		bool ret = 0;
		char *ApiName;
		WORD *NameOrd;
		DWORD i, ApiAddress, OriApiAddress;
		DWORD *Ent, *Eat, *OriEat;
		PE_INFO Pe, OrigPe;
		if (ParsePe((DWORD)ModuleInfo.ScanBuffer, &Pe) && ParsePe((DWORD)ModuleInfo.OrigBuffer, &OrigPe))
		{
			if (Pe.ExportSize)
			{
				Eat = (DWORD *)((DWORD)ModuleInfo.ScanBuffer + Pe.ExportTable->AddressOfFunctions);
				Ent = (DWORD *)((DWORD)ModuleInfo.ScanBuffer + Pe.ExportTable->AddressOfNames);
				NameOrd = (WORD *)((DWORD)ModuleInfo.ScanBuffer + Pe.ExportTable->AddressOfNameOrdinals);
				OriEat = (DWORD *)((DWORD)ModuleInfo.OrigBuffer + OrigPe.ExportTable->AddressOfFunctions);
				for (i = 0; i <= Pe.ExportTable->NumberOfNames; i++)
				{
					ApiAddress = Eat[NameOrd[i]] + ModuleInfo.DllBase;
					OriApiAddress = OriEat[NameOrd[i]] + ModuleInfo.DllBase;
					if (OriApiAddress >= (DWORD)Pe.ExportTable && (OriApiAddress < ((DWORD)Pe.ExportTable + Pe.ExportSize)))
						OriApiAddress = FileNameRedirection(ModuleInfo.DllBase, (char *)OriApiAddress);
					if (ApiAddress != OriApiAddress)
					{
						Info.HookType = EatHook;
						Info.OriginalAddress = OriApiAddress;
						Info.HookAddress = ApiAddress;
						memset(Info.HookedApiName, 0, 64);
						ApiName = (char *)(Ent[i] + ModuleInfo.DllBase);
						MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, Info.HookedApiName, 64);
						memset(Info.HookedModule, 0, 64);
						wcscpy_s(Info.HookedModule, 64, ModuleInfo.BaseName);
						if (!GetModulePathByAddress(hProcess, ApiAddress, Info.HookLocation))
							*(Info.HookLocation) = 0;
						HookInfo.push_back(Info);
					}
				}
				ret = 1;
			}
		}
		return ret;
	}

	bool ScanHook::ScanIatHook(MODULE_INFO ModuleInfo)
	{
		bool ret = 0, IsApiSet;
		char *DllName, *ApiName;
		WCHAR RealDllName[64];
		WORD Ordinal;
		DWORD ApiAddress, OriApiAddress;
		PIMAGE_THUNK_DATA FirstThunk, OriThunk;
		PIMAGE_IMPORT_BY_NAME ByName;
		PE_INFO Pe, OrigPe;
		if (ParsePe((DWORD)ModuleInfo.ScanBuffer, &Pe) && ParsePe((DWORD)ModuleInfo.OrigBuffer, &OrigPe))
		{
			if (Pe.ImportSize)
			{
				while (Pe.ImportTable->FirstThunk)
				{
					DllName = (char *)(Pe.ImportTable->Name + (DWORD)ModuleInfo.ScanBuffer);
					OriThunk = (PIMAGE_THUNK_DATA)(Pe.ImportTable->OriginalFirstThunk + (DWORD)ModuleInfo.ScanBuffer);
					FirstThunk = (PIMAGE_THUNK_DATA)(Pe.ImportTable->FirstThunk + (DWORD)ModuleInfo.ScanBuffer);
					while (FirstThunk->u1.Function)
					{
						ApiAddress = FirstThunk->u1.Function;
						if (OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						{
							Ordinal = OriThunk->u1.Ordinal & 0x0000FFFF;
							OriApiAddress = MyGetProcAddress(DllName, (char *)Ordinal, &IsApiSet, RealDllName);
						}
						else
						{
							ByName = (PIMAGE_IMPORT_BY_NAME)(OriThunk->u1.AddressOfData + (DWORD)ModuleInfo.ScanBuffer);
							ApiName = ByName->Name;
							OriApiAddress = MyGetProcAddress(DllName, ApiName, &IsApiSet, RealDllName);
						}
						if (ApiAddress != OriApiAddress)
						{
							Info.HookType = IatHook;
							Info.OriginalAddress = OriApiAddress;
							Info.HookAddress = ApiAddress;
							memset(Info.HookedApiName, 0, 64);
							MultiByteToWideChar(CP_ACP, 0, ApiName, strlen(ApiName) + 1, Info.HookedApiName, 64);
							memset(Info.HookedModule, 0, 64);
							if (IsApiSet)
								wcscpy_s(Info.HookedModule, 64, RealDllName);
							else
								MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, Info.HookedModule, 64);
							if (!GetModulePathByAddress(hProcess, ApiAddress, Info.HookLocation))
								*(Info.HookLocation) = 0;
							HookInfo.push_back(Info);
						}
						OriThunk++;
						FirstThunk++;
					}
					(Pe.ImportTable)++;
				}
			}
		}
		return ret;
	}

	bool  ScanHook::ElevatedPriv()
	{
		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			return 0;
		}
		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
		{
			return 0;
		}
		CloseHandle(hToken);
		return 1;
	}

	void ScanHook::GetWindowsVersion()
	{
		DWORD tem, tem2;
		__asm
		{
			mov eax, fs:[0x30]
			mov ebx, [eax + 0xa4]
			mov tem, ebx
			mov ebx, [eax + 0xa8]
			mov tem2, ebx
		}
		MajorVersion = tem;
		MinorVersion = tem2;
	}

	PDWORD ScanHook::GetApiSetMapHead()
	{
		DWORD *SetMapHead = 0;
		if ((MajorVersion >= 6) && (MinorVersion >= 1))
		{
			__asm
			{
				mov eax, fs:[0x30]
				mov eax, [eax + 0x38]
				mov SetMapHead, eax
			}
		}
		return SetMapHead;
	}

	bool ScanHook::CollectModuleInfo()
	{
		bool ret = 0;
		DWORD Peb;
		MODULE_INFO Info;
		PROCESS_BASIC_INFORMATION BaseInfo;
		PNT_PEB_LDR_DATA LdrData;
		LDR_DATA_TABLE_ENTRY Buffer;
		PLDR_DATA_TABLE_ENTRY LdrTable, EndLdrTable;
		if (!NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BaseInfo, sizeof(PROCESS_BASIC_INFORMATION), 0))
		{
			Peb = BaseInfo.PebBaseAddress;
			if (ReadProcessMemory(hProcess, (void *)(Peb + 0xc), &LdrData, 4, 0))
			{
				ReadProcessMemory(hProcess, &(LdrData->InLoadOrderModuleList), &LdrTable, 4, 0);
				ReadProcessMemory(hProcess, LdrTable, &Buffer, sizeof(LDR_DATA_TABLE_ENTRY), 0);
				EndLdrTable = LdrTable;
				do
				{
					Info.DllBase = (DWORD)Buffer.DllBase;
					Info.SizeOfImage = Buffer.SizeOfImage;
					memset(Info.FullName, 0, 260);
					ReadProcessMemory(hProcess, Buffer.FullDllName.Buffer, Info.FullName, Buffer.FullDllName.Length, 0);
					memset(Info.BaseName, 0, 64);
					ReadProcessMemory(hProcess, Buffer.BaseDllName.Buffer, Info.BaseName, Buffer.BaseDllName.Length, 0);
					Info.ScanBuffer = new BYTE[Buffer.SizeOfImage];
					ReadProcessMemory(hProcess, Buffer.DllBase, Info.ScanBuffer, Buffer.SizeOfImage, 0);
					Info.OrigBuffer = new BYTE[Buffer.SizeOfImage];
					PeLoader(Info.FullName, Info.OrigBuffer, Buffer.SizeOfImage);
					ModuleInfo.push_back(Info);
					ReadProcessMemory(hProcess, Buffer.InLoadOrderLinks.Flink, &Buffer, sizeof(LDR_DATA_TABLE_ENTRY), 0);
					LdrTable = (PLDR_DATA_TABLE_ENTRY)(Buffer.InLoadOrderLinks.Flink);
				} while (LdrTable != EndLdrTable);
				ret = 1;
			}
		}
		return ret;
	}

	bool ScanHook::PeLoader(WCHAR *FilePath, void *BaseAddress, DWORD BufferSize)
	{
		bool ret = 0;
		BYTE *Buffer;
		DWORD SectionNum, HeadSize, DateSize;
		HANDLE hFile;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_NT_HEADERS PeHead;
		PIMAGE_SECTION_HEADER SectionHead;
		if (BaseAddress)
		{
			hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				Buffer = new BYTE[BufferSize];
				if (Buffer)
				{
					if (ReadFile(hFile, Buffer, BufferSize, 0, 0))
					{
						DosHead = (PIMAGE_DOS_HEADER)Buffer;
						PeHead = (PIMAGE_NT_HEADERS)((DWORD)DosHead + DosHead->e_lfanew);
						SectionHead = IMAGE_FIRST_SECTION(PeHead);
						SectionNum = PeHead->FileHeader.NumberOfSections;
						HeadSize = PeHead->OptionalHeader.SizeOfHeaders;
						memset(BaseAddress, 0, BufferSize);
						memcpy(BaseAddress, Buffer, HeadSize);
						for (DWORD i = 0; i < SectionNum; i++)
						{
							DateSize = SectionHead[i].SizeOfRawData;
							if (DateSize > SectionHead[i].Misc.VirtualSize)
								DateSize = SectionHead[i].Misc.VirtualSize;
							memcpy((void *)((DWORD)BaseAddress + SectionHead[i].VirtualAddress),
								(void *)((DWORD)Buffer + SectionHead[i].PointerToRawData), DateSize);
						}
						FixRelocTable((DWORD)Buffer, (DWORD)BaseAddress);
						ret = 1;
					}
					delete[] Buffer;
				}
			}
		}
		return ret;
	}

	void ScanHook::FixRelocTable(DWORD hModule, DWORD BaseAddress)
	{
		USHORT *Fixup;
		DWORD RelocSize, *RelocAddress;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_NT_HEADERS PeHead;
		PIMAGE_BASE_RELOCATION RelocTable;
		DosHead = (PIMAGE_DOS_HEADER)hModule;
		PeHead = (PIMAGE_NT_HEADERS)((DWORD)DosHead + DosHead->e_lfanew);
		if (BaseAddress == PeHead->OptionalHeader.ImageBase)
			return;
		RelocSize = ((DWORD)BaseAddress + PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		if (!RelocSize)
			return;
		RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)BaseAddress 
			+ PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		Fixup = (USHORT *)((DWORD)RelocTable + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD i = 0; i < ((RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++)
		{
			if ((Fixup[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
			{
				RelocAddress = (DWORD *)((Fixup[i] & 0xfff) + hModule + RelocTable->VirtualAddress);
				*RelocAddress = *RelocAddress - PeHead->OptionalHeader.ImageBase + BaseAddress;
			}
		}
	}

	bool ScanHook::ParsePe(DWORD ImageBase, PPE_INFO PeInfo)
	{
		bool ret = 0;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_OPTIONAL_HEADER OpitionHead;
		if (ImageBase)
		{
			DosHead = (PIMAGE_DOS_HEADER)ImageBase;
			if (DosHead->e_magic ==IMAGE_DOS_SIGNATURE)
			{
				PeInfo->PeHead = (PIMAGE_NT_HEADERS)(ImageBase + DosHead->e_lfanew);
				if (PeInfo->PeHead->Signature == IMAGE_NT_SIGNATURE)
				{
					OpitionHead = &(PeInfo->PeHead->OptionalHeader);
					PeInfo->ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase 
						+ OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					PeInfo->ExportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					PeInfo->ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(ImageBase 
						+ OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
					PeInfo->ImportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					ret = 1;
				}
			}
		}
		return ret;
	}

	DWORD ScanHook::GetExportByOrdinal(DWORD ModuleBase, WORD Ordinal)
	{
		DWORD ApiAddress = 0;
		DWORD *Eat;
		PE_INFO PeInfo;
		ParsePe(ModuleBase, &PeInfo);
		if (PeInfo.ExportSize)
		{
			Eat = (DWORD *)(ModuleBase + PeInfo.ExportTable->AddressOfFunctions);
			ApiAddress = ((Eat[Ordinal - PeInfo.ExportTable->Base] != 0) ? (ModuleBase + Eat[Ordinal - PeInfo.ExportTable->Base]) : 0);
			if ((ApiAddress >= (DWORD)PeInfo.ExportTable) &&
				(ApiAddress < ((DWORD)PeInfo.ExportTable + PeInfo.ExportSize)))
				ApiAddress = FileNameRedirection(ModuleBase, (char *)ApiAddress);
		}
		return ApiAddress;
	}

	DWORD ScanHook::GetExportByName(DWORD ModuleBase, char *ProcName)
	{
		int cmp;
		char *ApiName;
		DWORD ApiAddress = 0;
		WORD Ordinal, *NameOrd;
		DWORD *Ent, *Eat, HigthIndex, LowIndex = 0, MidIndex;
		PE_INFO PeInfo;
		ParsePe(ModuleBase, &PeInfo);
		if (PeInfo.ExportSize)
		{
			Eat = (DWORD *)(ModuleBase + PeInfo.ExportTable->AddressOfFunctions);
			Ent = (DWORD *)(ModuleBase + PeInfo.ExportTable->AddressOfNames);
			NameOrd = (WORD *)(ModuleBase + PeInfo.ExportTable->AddressOfNameOrdinals);
			HigthIndex = PeInfo.ExportTable->NumberOfNames ;
			while (LowIndex <= HigthIndex)
			{
				MidIndex = (LowIndex + HigthIndex) / 2;
				ApiName = (char *)(ModuleBase + Ent[MidIndex]);
				__try
				{
					cmp = strcmp(ProcName, ApiName);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return 0;
				}
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
			ApiAddress = (ModuleBase + Eat[Ordinal]);
			if (ApiAddress >= (DWORD)PeInfo.ExportTable &&
				(ApiAddress < ((DWORD)PeInfo.ExportTable + PeInfo.ExportSize)))
			{
				ApiAddress = FileNameRedirection(ModuleBase, (char *)ApiAddress);
				IsRedirction = 1;
			}
		}
		return ApiAddress;
	}

	DWORD ScanHook::FileNameRedirection(DWORD ModuleBase, char *RedirectionName)
	{
		char *ptr, *ProcName;
		char Buffer[64];
		WCHAR DllName[64];
		DWORD ApiAddress = 0;
		strcpy_s(Buffer, 64, RedirectionName);
		ptr = strchr(Buffer, '.');
		if (ptr)
		{
			*ptr = 0;
			MultiByteToWideChar(CP_ACP, 0, Buffer, sizeof(Buffer), DllName, 64);
			if (!_wcsnicmp(DllName, L"api-", 4))
			{
				IsFromRedirction = 1;
				ResolveApiSet(DllName, DllName, 64);
				IsFromRedirction = 0;
				goto get_api_address;
			}
			else
			{
			get_api_address:
				ModuleBase = (DWORD)LoadLibraryW(DllName);
				if (ModuleBase)
				{
					ProcName = (char *)(ptr + 1);
					ApiAddress = GetExportByName(ModuleBase, ProcName);
					FreeLibrary((HMODULE)ModuleBase);
				}
			}
		}
		return ApiAddress;
	}

	bool ScanHook::ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size)
	{
		bool ret = 0;
		WCHAR *NameBuffer, *ptr;
		WCHAR LibName[64];
		DWORD ApiAddress = 0, LibNameSize, HostNameSize;
		DWORD *Version;;
		PAPI_SET_NAMESPACE_ARRAY_V2 SetMapHead_v2;
		PAPI_SET_VALUE_ARRAY_V2 SetMapHost_v2;
		PAPI_SET_NAMESPACE_ARRAY_V4 SetMapHead_v4;
		PAPI_SET_VALUE_ARRAY_V4 SetMapHost_v4;
		Version = ApiSetMapHead;
		ptr = wcschr(ApiSetName, L'.');
		if (ptr)
			*ptr = 0;
		if (Version)
		{
			switch (*Version)
			{
			case 2:
			{
					  SetMapHead_v2 = (PAPI_SET_NAMESPACE_ARRAY_V2)Version;
					  for (DWORD i = 0; i < SetMapHead_v2->Count; i++)
					  {
						  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHead_v2->Entry[i].NameOffset);
						  LibNameSize = SetMapHead_v2->Entry[i].NameLength;
						  wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
						  if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
						  {
							  SetMapHost_v2 = (PAPI_SET_VALUE_ARRAY_V2)((DWORD)SetMapHead_v2 + SetMapHead_v2->Entry[i].DataOffset);
							  if (SetMapHost_v2->Count == 1)
							  {
								  HostNameSize = SetMapHost_v2->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[0].ValueOffset);
							  }
							  else
							  {
								  HostNameSize = SetMapHost_v2->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[0].ValueOffset);
								  if (!_wcsnicmp(Moduleiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsFromRedirction)
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
					  SetMapHead_v4 = (PAPI_SET_NAMESPACE_ARRAY_V4)Version;
					  for (DWORD i = 0; i < SetMapHead_v4->Count; i++)
					  {
						  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHead_v4->Entry[i].NameOffset);
						  LibNameSize = SetMapHead_v4->Entry[i].NameLength;
						  wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
						  if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
						  {
							  SetMapHost_v4 = (PAPI_SET_VALUE_ARRAY_V4)((DWORD)SetMapHead_v4 + SetMapHead_v4->Entry[i].DataOffset);
							  if (SetMapHost_v4->Count == 1)
							  {
								  HostNameSize = SetMapHost_v4->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[0].ValueOffset);
							  }
							  else
							  {
								  HostNameSize = SetMapHost_v4->Entry[0].ValueLength;
								  NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[0].ValueOffset);
								  if (!_wcsnicmp(Moduleiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsFromRedirction)
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

	DWORD ScanHook::MyGetProcAddress(char *DllName, char *ApiName, bool *IsApiSet, WCHAR *RealDllName)
	{
		bool IsExist = 0;
		DWORD ApiAddress = 0;
		WCHAR NameBuffer[64], HostName[64];
		vector<MODULE_INFO>::iterator iter;
		*IsApiSet = 0;
		MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, NameBuffer, 64);
		if (HIWORD((DWORD)ApiName))
		{
			for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); iter++)
			{
				if (!_wcsicmp(iter->BaseName, NameBuffer))
				{
					ApiAddress = GetExportByName((DWORD)iter->OrigBuffer, ApiName);
					if (!IsRedirction)
						ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
					IsRedirction = 0;
					IsExist = 1;
					break;
				}
			}
			if (!IsExist && !_wcsnicmp(NameBuffer, L"api-", 4) && (MajorVersion >= 6 && MinorVersion >= 1))
			{
				if (ResolveApiSet(NameBuffer, HostName, 64))
				{
					*IsApiSet = 1;
					wcscpy_s(RealDllName, 64, HostName);
					for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); iter++)
					{
						if (!_wcsicmp(HostName, iter->BaseName))
						{
							ApiAddress = GetExportByName((DWORD)iter->OrigBuffer, ApiName);
							if (!IsRedirction)
								ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
							IsRedirction = 0;
							break;
						}
					}
				}
			}
		}
		else
		{
			for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); iter++)
			{
				if (!_wcsicmp(iter->BaseName, NameBuffer))
				{
					ApiAddress = GetExportByOrdinal((DWORD)iter->OrigBuffer, (WORD)ApiName);
					ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
					break;
				}
			}
		}
		return ApiAddress;
	}

	DWORD ScanHook::GetModulePathByAddress(HANDLE hProcess, DWORD Address, WCHAR *ModulePath)
	{
		DWORD Buffer;
		Address &= 0xFFFF0000;
		while (Address)
		{
			if (ReadProcessMemory(hProcess, (void *)Address, &Buffer, 4, 0))
				if ((WORD)Buffer == IMAGE_DOS_SIGNATURE)
					if (ReadProcessMemory(hProcess, (void *)(Address + 0x3C), &Buffer, 4, 0))
						if (ReadProcessMemory(hProcess, (void *)(Buffer + Address), &Buffer, 4, 0))
						   if (Buffer == IMAGE_NT_SIGNATURE)
							   break;
			Address -= 0x10000;
		}
		if (!Address)
			return 0;
		return GetModuleFileNameEx(hProcess, (HMODULE)Address, ModulePath, 260);
	}
}