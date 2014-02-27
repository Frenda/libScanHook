#include "libScanHook.h"

namespace libScanHook
{
	ScanHook::ScanHook()
	{
		IsRedirction = 0;
		IsFromRedirction = 0;
		ElevatedPriv();
	}

	bool ScanHook::InitScan(DWORD Pid)
	{
		bool ret = 0;
		if (CollectSystemInfo())
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
			if (hProcess)
			{
				if (CollectModuleInfo())
				{
					for (ModuleInfoiter = ModuleInfo.begin(); ModuleInfoiter != ModuleInfo.end(); ++ModuleInfoiter)
					{
						ScanEatHook(*ModuleInfoiter);
						ScanIatHook(*ModuleInfoiter);
					}
					ret = 1;
					HookInfoiter = HookInfo.begin();
				}
				CloseHandle(hProcess);
			}
		}
		return ret;
	}

	void ScanHook::CloseScan()
	{
		vector<MODULE_INFO>::iterator iter;
		for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); ++iter)
		{
			if (iter->ScanBuffer)
				delete[] iter->ScanBuffer;
			if (iter->OrigBuffer)
				delete[] iter->OrigBuffer;
		}
		ModuleInfo.clear();
		HookInfo.clear();
	}

	bool ScanHook::GetProcessHookInfo(PPROCESS_HOOK_INFO Entry)
	{
		bool ret = 0;
		if (HookInfoiter != HookInfo.end())
		{
			Entry->HookType = HookInfoiter->HookType;
			Entry->OriginalAddress = HookInfoiter->OriginalAddress;
			Entry->HookAddress = HookInfoiter->HookAddress;
			memset(Entry->HookedApiName, 0, 64 * sizeof(WCHAR ));
			wcscpy_s(Entry->HookedApiName, 64, HookInfoiter->HookedApiName);
			memset(Entry->HookedModule, 0, 64 * sizeof(WCHAR));
			wcscpy_s(Entry->HookedModule, 64, HookInfoiter->HookedModule);
			memset(Entry->HookLocation, 0, 260 * sizeof(WCHAR));
			wcscpy_s(Entry->HookLocation, 260, HookInfoiter->HookLocation);
			++HookInfoiter;
			ret = 1;
		}
		return ret;
	}

	bool ScanHook::ScanInlineHook(char *ApiName, DWORD ApiAddress)
	{
		bool ret = 0;
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
				for (i = 0; i < Pe.ExportTable->NumberOfNames; i++)
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
						GetModulePathByAddress(ApiAddress, Info.HookLocation);
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
							GetModulePathByAddress(ApiAddress, Info.HookLocation);
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

	bool ScanHook::CollectSystemInfo()
	{
		bool ret = 0;
		PNT_PEB Peb;
		NT_PROCESS_BASIC_INFORMATION BaseInfo;
		if (!NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &BaseInfo, sizeof(NT_PROCESS_BASIC_INFORMATION), 0))
		{
			Peb = (PNT_PEB)(BaseInfo.PebBaseAddress);
			MajorVersion = Peb->OSMajorVersion;
			MinorVersion = Peb->OSMinorVersion;
			if (MajorVersion >= 6 && MinorVersion >= 1)
				ApiSetMapHead = (DWORD *)(Peb->ApiSetMap);
			ret = 1;
		}
		return ret;
	}

	bool ScanHook::CollectModuleInfo()
	{
		bool ret = 0;
		DWORD Peb;
		MODULE_INFO Info;
		NT_PROCESS_BASIC_INFORMATION BaseInfo;
		PNT_PEB_LDR_DATA LdrData;
		NT_LDR_DATA_TABLE_ENTRY Buffer;
		PNT_LDR_DATA_TABLE_ENTRY LdrTable, EndLdrTable;
		if (!NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BaseInfo, sizeof(NT_PROCESS_BASIC_INFORMATION), 0))
		{
			Peb = BaseInfo.PebBaseAddress;
			__try
			{
				ReadProcessMemory(hProcess, (void *)(Peb + 0xc), &LdrData, 4, 0);
				ReadProcessMemory(hProcess, &(LdrData->InLoadOrderModuleList), &LdrTable, 4, 0);
				ReadProcessMemory(hProcess, LdrTable, &Buffer, sizeof(NT_LDR_DATA_TABLE_ENTRY), 0);
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
					PeLoader(Info.FullName, Info.OrigBuffer, Buffer.SizeOfImage, (DWORD)Buffer.DllBase);
					ModuleInfo.push_back(Info);
					ReadProcessMemory(hProcess, Buffer.InLoadOrderLinks.Flink, &Buffer, sizeof(NT_LDR_DATA_TABLE_ENTRY), 0);
					LdrTable = (PNT_LDR_DATA_TABLE_ENTRY)(Buffer.InLoadOrderLinks.Flink);
				} while (LdrTable != EndLdrTable);
				ret = 1;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ret = 0;
			}
		}
		return ret;
	}

	bool ScanHook::PeLoader(WCHAR *FilePath, void *BaseAddress, DWORD BufferSize, DWORD DllBase)
	{
		bool ret = 0;
		void *Buffer;
		DWORD SectionNum, HeadSize, DateSize;
		HANDLE hFile;
		PE_INFO Pe;
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
						ParsePe((DWORD)Buffer, &Pe);
						SectionHead = IMAGE_FIRST_SECTION(Pe.PeHead);
						SectionNum = Pe.PeHead->FileHeader.NumberOfSections;
						HeadSize = Pe.PeHead->OptionalHeader.SizeOfHeaders;
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
						FixRelocTable(DllBase, (DWORD)BaseAddress);
						ret = 1;
					}
					delete[] Buffer;
				}
				CloseHandle(hFile);
			}
		}
		return ret;
	}

	void ScanHook::FixRelocTable(DWORD ModuleBase, DWORD NewModuleBase)
	{
		WORD Type, Offset;
		WORD *RelocInfo;
		DWORD Dest, RelocSize, RelocOffset, RelocInfoNum;
		DWORD *NewAddr;
		PE_INFO Pe;
		PIMAGE_BASE_RELOCATION RelocTable;
		if (ParsePe(NewModuleBase, &Pe))
		{
			RelocSize = (NewModuleBase + Pe.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			if (RelocSize != 0)
			{
				RelocTable = (PIMAGE_BASE_RELOCATION)(NewModuleBase +
					Pe.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				if (ModuleBase != Pe.PeHead->OptionalHeader.ImageBase)
				{
					RelocOffset = ModuleBase - Pe.PeHead->OptionalHeader.ImageBase;
					while (RelocTable->VirtualAddress != 0)
					{
						Dest = NewModuleBase + RelocTable->VirtualAddress;
						RelocInfoNum = RelocTable->SizeOfBlock - (sizeof(IMAGE_BASE_RELOCATION) / 2);
						RelocInfo = (WORD *)((DWORD)RelocTable + sizeof(IMAGE_BASE_RELOCATION));
						while (RelocInfoNum)
						{
							__try
							{
								Type = *RelocInfo >> 12;
								Offset = *RelocInfo & 0xfff;
								switch (Type)
								{
								case IMAGE_REL_BASED_HIGHLOW:
									NewAddr = (DWORD *)(Dest + Offset);
									*(DWORD *)NewAddr += RelocOffset;
									break;
								case IMAGE_REL_BASED_DIR64:
									break;
								case IMAGE_REL_BASED_ABSOLUTE:
								default:
									break;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								RelocInfoNum--;
							}
							RelocInfoNum--;
						}
						RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)RelocTable + RelocTable->SizeOfBlock);
					}
				}
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
			__try
			{
				while (LowIndex <= HigthIndex)
				{
					MidIndex = (LowIndex + HigthIndex) / 2;
					ApiName = (char *)(ModuleBase + Ent[MidIndex]);
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
				ApiAddress = (ModuleBase + Eat[Ordinal]);
				if (ApiAddress >= (DWORD)PeInfo.ExportTable &&
					(ApiAddress < ((DWORD)PeInfo.ExportTable + PeInfo.ExportSize)))
				{
					ApiAddress = FileNameRedirection(ModuleBase, (char *)ApiAddress);
					IsRedirction = 1;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return 0;
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
		PNT_API_SET_NAMESPACE_ARRAY_V2 SetMapHead_v2;
		PNT_API_SET_VALUE_ARRAY_V2 SetMapHost_v2;
		PNT_API_SET_NAMESPACE_ARRAY_V4 SetMapHead_v4;
		PNT_API_SET_VALUE_ARRAY_V4 SetMapHost_v4;
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
								  if (!_wcsnicmp(ModuleInfoiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsFromRedirction)
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
								  if (!_wcsnicmp(ModuleInfoiter->BaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsFromRedirction)
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
		DWORD ApiAddress = 0;
		WCHAR NameBuffer[64], HostName[64];
		vector<MODULE_INFO>::iterator iter;
		*IsApiSet = 0;
		MultiByteToWideChar(CP_ACP, 0, DllName, strlen(DllName) + 1, NameBuffer, 64);
		if (HIWORD((DWORD)ApiName))
		{
			if (GetModuleInfomation(NameBuffer, iter))
			{
				ApiAddress = GetExportByName((DWORD)iter->OrigBuffer, ApiName);
				if (!IsRedirction)
					ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
				IsRedirction = 0;
			}
			else
			{
				if (!_wcsnicmp(NameBuffer, L"api-", 4) && (MajorVersion >= 6 && MinorVersion >= 1))
				{
					if (ResolveApiSet(NameBuffer, HostName, 64))
					{
						*IsApiSet = 1;
						if (GetModuleInfomation(HostName, iter))
						{
							ApiAddress = GetExportByName((DWORD)iter->OrigBuffer, ApiName);
							if (!IsRedirction)
								ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
							IsRedirction = 0;
						}
					}
				}
			}
		}
		else
		{
			if (GetModuleInfomation(NameBuffer, iter))
			{
				ApiAddress = GetExportByOrdinal((DWORD)iter->OrigBuffer, (WORD)ApiName);
				ApiAddress = ApiAddress - (DWORD)iter->OrigBuffer + iter->DllBase;
			}
		}
		return ApiAddress;
	}

	bool ScanHook::GetModuleInfomation(WCHAR *DllName, vector<MODULE_INFO>::iterator &iter)
	{
		bool ret = 0;
		vector<MODULE_INFO>::iterator enditer;
		enditer = ModuleInfo.end();
		for (iter = ModuleInfo.begin(); iter != enditer; ++iter)
		{
			if (!_wcsicmp(iter->BaseName, DllName))
			{
				ret = 1;
				break;
			}
		}
		return ret;
	}

	void ScanHook::GetModulePath(DWORD Address, WCHAR *ModulePath)
	{
		vector<MODULE_INFO>::iterator iter, enditer;
		enditer = ModuleInfo.end();
		for (iter = ModuleInfo.begin(); iter != enditer; ++iter)
		{
			if (iter->DllBase == Address)
				wcscpy_s(ModulePath, 260, iter->FullName);
		}
	}

	void ScanHook::GetModulePathByAddress(DWORD Address, WCHAR *ModulePath)
	{
		DWORD Buffer;
		memset(ModulePath, 0, 260);
		Address &= 0xFFFF0000;
		__try
		{
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
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
		if (Address)
			GetModulePath(Address, ModulePath);
	}
}