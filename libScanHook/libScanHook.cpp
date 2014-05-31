#include "libScanHook.h"

namespace libScanHook
{
	ScanHook::ScanHook()
	{
		m_IsFromIat = 0;
		m_IsFromEat = 0;
		ElevatedPriv();
	}

	bool ScanHook::InitScan(DWORD Pid)
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

	void ScanHook::CloseScan()
	{
		for (ModuleInfoiter = ModuleInfo.begin(); ModuleInfoiter != ModuleInfo.end(); ++ModuleInfoiter)
		{
			if (ModuleInfoiter->DiskImage)
				delete[] ModuleInfoiter->DiskImage;
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
			wcscpy_s(Entry->HookedApiName, 128, HookInfoiter->HookedApiName);
			wcscpy_s(Entry->HookedModule, 64, HookInfoiter->HookedModule);
			wcscpy_s(Entry->HookLocation, 260, HookInfoiter->HookLocation);
			++HookInfoiter;
			ret = 1;
		}
		return ret;
	}

	bool ScanHook::ScanInlineHook(char *ApiName, DWORD Address)
	{
		bool ret = 0, IsHook = 0;
		DWORD Dest, Src, Index, InstrLen, HookAddress = 0;
		vector<MODULE_INFO>::iterator iter;
		INSTRUCTION Instr, Instr2;
		if (GetModuleInfomation(Address, iter))
		{
			Dest = Address - iter->DllBase + (DWORD)iter->MemoryImage;
			Src = Address - iter->DllBase + (DWORD)iter->DiskImage;
			for (Index = 0; Index < 10; ++Index)
			{
				if ((*(BYTE *)(Dest + Index)) != (*(BYTE *)(Src + Index)))
				{
					InstrLen = get_instruction(&Instr, ((BYTE *)(Dest + Index)), MODE_32);
					switch (Instr.type)
					{
					case INSTRUCTION_TYPE_JMP:
					{
						if (Instr.length == 7)
							HookAddress = Instr.op1.displacement;
						if (Instr.length == 5)
							HookAddress = Dest + Index + Instr.op1.displacement;
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


	bool ScanHook::ScanEatHook()
	{
		bool ret = 0;
		char *ApiName;
		WORD *NameOrd;
		DWORD tem, tem1;
		DWORD i, ApiAddress, OriApiAddress, Tem;
		DWORD *Ent, *Eat, *OriEat;
		PE_INFO Pe, OrigPe;
		vector<MODULE_INFO>::iterator iter;
		PIMAGE_EXPORT_DIRECTORY ExporTable, OrigExportTable;
		if (ParsePe((DWORD)ModuleInfoiter->MemoryImage, &Pe) && ParsePe((DWORD)ModuleInfoiter->DiskImage, &OrigPe))
		{
			if (Pe.ExportSize)
			{
				ExporTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)ModuleInfoiter->MemoryImage + Pe.ExportTableRva);
				OrigExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)ModuleInfoiter->DiskImage + Pe.ExportTableRva);
				Eat = (DWORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfFunctions);
				Ent = (DWORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfNames);
				NameOrd = (WORD *)((DWORD)ModuleInfoiter->MemoryImage + ExporTable->AddressOfNameOrdinals);
				OriEat = (DWORD *)((DWORD)ModuleInfoiter->DiskImage + OrigExportTable->AddressOfFunctions);
				for (i = 0; i < ExporTable->NumberOfNames; ++i)
				{
					if (IsGlobalVar(OrigPe.PeHead, OriEat[NameOrd[i]]))
						continue;
					tem = Eat[NameOrd[i]];
					tem1 = OriEat[NameOrd[i]];
					ApiName = (char *)(Ent[i] + (DWORD)ModuleInfoiter->DiskImage);
					ApiAddress = Eat[NameOrd[i]] + ModuleInfoiter->DllBase;
					OriApiAddress = OriEat[NameOrd[i]] + ModuleInfoiter->DllBase;
					Tem = OriEat[NameOrd[i]] + (DWORD)ModuleInfoiter->DiskImage;
					if (Tem >= (DWORD)OrigExportTable && Tem < ((DWORD)OrigExportTable + Pe.ExportSize))
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

	bool ScanHook::ScanIatHook()
	{
		bool ret = 0, IsApiSet;
		char *DllName, *ApiName;
		char OrdinalName[13];
		WCHAR RealDllName[64];
		WORD Ordinal;
		DWORD ApiAddress, OriApiAddress;
		PIMAGE_THUNK_DATA FirstThunk, OriThunk;
		PIMAGE_IMPORT_BY_NAME ByName;
		PE_INFO Pe;
		PIMAGE_IMPORT_DESCRIPTOR ImportTable;
		if (ParsePe((DWORD)ModuleInfoiter->MemoryImage, &Pe))
		{
			if (Pe.ImportSize)
			{
				ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)ModuleInfoiter->MemoryImage + Pe.ImportTableRva);
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

	void ScanHook::AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, WCHAR *HookedModule)
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

	void ScanHook::AddHookInfoToList(DWORD HookType, DWORD OriginalAddress, DWORD HookAddress, char *HookedApiName, char *HookedModule)
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

	bool ScanHook::QuerySystemInfo()
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

	bool ScanHook::QueryModuleInfo()
	{
		bool ret = 0;
		DWORD Peb;
		MODULE_INFO Info;
		NT_PROCESS_BASIC_INFORMATION BaseInfo;
		PNT_PEB_LDR_DATA LdrData;
		NT_LDR_DATA_TABLE_ENTRY Buffer;
		PNT_LDR_DATA_TABLE_ENTRY LdrTable, EndLdrTable;
		if (!NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &BaseInfo, sizeof(NT_PROCESS_BASIC_INFORMATION), 0))
		{
			Peb = BaseInfo.PebBaseAddress;
			__try
			{
				if (ReadProcessMemory(m_hProcess, (void *)(Peb + 0xc), &LdrData, 4, 0))
				{
					if (ReadProcessMemory(m_hProcess, &(LdrData->InLoadOrderModuleList), &LdrTable, 4, 0))
					{
						if (ReadProcessMemory(m_hProcess, LdrTable, &Buffer, sizeof(NT_LDR_DATA_TABLE_ENTRY), 0))
						{
							EndLdrTable = LdrTable;
							do
							{
								memset(&Info, 0, sizeof(MODULE_INFO));
								Info.DllBase = (DWORD)Buffer.DllBase;
								Info.SizeOfImage = Buffer.SizeOfImage;
								ReadProcessMemory(m_hProcess, Buffer.FullDllName.Buffer, Info.FullName, Buffer.FullDllName.Length, 0);
								ReadProcessMemory(m_hProcess, Buffer.BaseDllName.Buffer, Info.BaseName, Buffer.BaseDllName.Length, 0);
								Info.DiskImage = new BYTE[Buffer.SizeOfImage];
								PeLoader(Info.FullName, (DWORD)Buffer.DllBase, Info.DiskImage, Buffer.SizeOfImage);
								ModuleInfo.push_back(Info);
								ReadProcessMemory(m_hProcess, Buffer.InLoadOrderLinks.Flink, &Buffer, sizeof(NT_LDR_DATA_TABLE_ENTRY), 0);
								LdrTable = (PNT_LDR_DATA_TABLE_ENTRY)(Buffer.InLoadOrderLinks.Flink);
							} while (LdrTable != EndLdrTable);
							ret = 1;
						}
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ret = 0;
			}
		}
		return ret;
	}

	bool ScanHook::ReadMemoryImage()
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

	void ScanHook::FreeMemoryImage()
	{
		if (ModuleInfoiter->MemoryImage)
		{
			delete[] ModuleInfoiter->MemoryImage;
			ModuleInfoiter->MemoryImage = 0;
		}
	}

	bool ScanHook::PeLoader(WCHAR *FilePath, DWORD DllBase, void *Buffer, DWORD BufferSize)
	{
		bool ret = 0;
		void *FileBuffer;
		DWORD SectionNum, HeaderSize, DateSize, FileAlignment, SectionAlignment, i;
		HANDLE hFile;
		PE_INFO Pe;
		PIMAGE_SECTION_HEADER SectionHead;
		if (Buffer)
		{
			hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				FileBuffer = new BYTE[BufferSize];
				if (FileBuffer)
				{
					if (ReadFile(hFile, FileBuffer, BufferSize, 0, 0))
					{
						ParsePe((DWORD)FileBuffer, &Pe);
						SectionHead = IMAGE_FIRST_SECTION(Pe.PeHead);
						SectionNum = Pe.PeHead->FileHeader.NumberOfSections;
						HeaderSize = Pe.PeHead->OptionalHeader.SizeOfHeaders;
						FileAlignment = Pe.PeHead->OptionalHeader.FileAlignment;
						SectionAlignment = Pe.PeHead->OptionalHeader.SectionAlignment;
						memset(Buffer, 0, BufferSize);
						memcpy(Buffer, FileBuffer, HeaderSize);
						for (i = 0; i < SectionNum; ++i)
						{
							SectionHead[i].SizeOfRawData = AlignSize(SectionHead[i].SizeOfRawData, FileAlignment);
							SectionHead[i].Misc.VirtualSize = AlignSize(SectionHead[i].Misc.VirtualSize, SectionAlignment);
						}
						if (SectionHead[SectionNum - 1].VirtualAddress + SectionHead[SectionNum - 1].SizeOfRawData > BufferSize)
							SectionHead[SectionNum - 1].SizeOfRawData = BufferSize - SectionHead[SectionNum - 1].VirtualAddress;
						for (i = 0; i < SectionNum; ++i)
						{
							DateSize = SectionHead[i].SizeOfRawData;
							memcpy((void *)((DWORD)Buffer + SectionHead[i].VirtualAddress),
								(void *)((DWORD)FileBuffer + SectionHead[i].PointerToRawData), DateSize);
						}
						FixBaseRelocTable((DWORD)Buffer, DllBase);
						ret = 1;
					}
					delete[] FileBuffer;
				}
				CloseHandle(hFile);
			}
		}
		return ret;
	}

	UINT ScanHook::AlignSize(UINT Size, UINT Align)
	{
		return ((Size + Align - 1) / Align * Align);
	}

	bool ScanHook::FixBaseRelocTable(ULONG_PTR NewImageBase, ULONG_PTR ExistImageBase)
	{
		LONGLONG Diff;
		ULONG TotalCountBytes, SizeOfBlock;
		ULONG_PTR VA;
		ULONGLONG OriginalImageBase;
		PUSHORT NextOffset = 0;
		PE_INFO Pe;
		PIMAGE_BASE_RELOCATION NextBlock;
		ParsePe(NewImageBase, &Pe);
		if (Pe.PeHead == 0)
			return 0;
		switch (Pe.PeHead->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS32)Pe.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS64)Pe.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		default:
			return 0;
		}
		NextBlock = (PIMAGE_BASE_RELOCATION)(NewImageBase +
			Pe.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		TotalCountBytes = Pe.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (!NextBlock || !TotalCountBytes)
		{
			if (Pe.PeHead->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
				return 0;
			else
				return 1;
		}
		Diff = ExistImageBase - OriginalImageBase;
		while (TotalCountBytes)
		{
			SizeOfBlock = NextBlock->SizeOfBlock;
			TotalCountBytes -= SizeOfBlock;
			SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
			SizeOfBlock /= sizeof(USHORT);
			NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));
			VA = NewImageBase + NextBlock->VirtualAddress;
			NextBlock = ProcessRelocationBlock(VA, SizeOfBlock, NextOffset, Diff);
			if (!NextBlock)
				return 0;
		}
		return 1;
	}

	PIMAGE_BASE_RELOCATION ScanHook::ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff)
	{
		PUCHAR FixupVA;
		USHORT Offset;
		LONG Temp;
		ULONGLONG Value64;
		while (SizeOfBlock--)
		{
			Offset = *NextOffset & (USHORT)0xfff;
			FixupVA = (PUCHAR)(VA + Offset);
			switch ((*NextOffset) >> 12)
			{
			case IMAGE_REL_BASED_HIGHLOW:
			{
				*(LONG UNALIGNED *)FixupVA += (ULONG)Diff;
				break;
			}
			case IMAGE_REL_BASED_HIGH:
			{
				Temp = *(PUSHORT)FixupVA & 16;
				Temp += (ULONG)Diff;
				*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
				break;
			}
			case IMAGE_REL_BASED_HIGHADJ:
			{
				if (Offset & LDRP_RELOCATION_FINAL)
				{
					++NextOffset;
					--SizeOfBlock;
					break;
				}
				Temp = *(PUSHORT)FixupVA & 16;
				++NextOffset;
				--SizeOfBlock;
				Temp += (LONG)(*(PSHORT)NextOffset);
				Temp += (ULONG)Diff;
				Temp += 0x8000;
				*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
				break;
			}
			case IMAGE_REL_BASED_LOW:
			{
				Temp = *(PSHORT)FixupVA;
				Temp += (ULONG)Diff;
				*(PUSHORT)FixupVA = (USHORT)Temp;
				break;
			}
			case IMAGE_REL_BASED_IA64_IMM64:
			{
				FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
				Value64 = (ULONGLONG)0;
				EXT_IMM64(Value64,
					(PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
					EMARCH_ENC_I17_IMM7B_SIZE_X,
					EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM7B_VAL_POS_X);
				EXT_IMM64(Value64,
					(PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
					EMARCH_ENC_I17_IMM9D_SIZE_X,
					EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM9D_VAL_POS_X);
				EXT_IMM64(Value64,
					(PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
					EMARCH_ENC_I17_IMM5C_SIZE_X,
					EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM5C_VAL_POS_X);
				EXT_IMM64(Value64,
					(PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
					EMARCH_ENC_I17_IC_SIZE_X,
					EMARCH_ENC_I17_IC_INST_WORD_POS_X,
					EMARCH_ENC_I17_IC_VAL_POS_X);
				EXT_IMM64(Value64,
					(PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
					EMARCH_ENC_I17_IMM41a_SIZE_X,
					EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41a_VAL_POS_X);
				EXT_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
					EMARCH_ENC_I17_IMM41b_SIZE_X,
					EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41b_VAL_POS_X);
				EXT_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
					EMARCH_ENC_I17_IMM41c_SIZE_X,
					EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41c_VAL_POS_X);
				EXT_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
					EMARCH_ENC_I17_SIGN_SIZE_X,
					EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
					EMARCH_ENC_I17_SIGN_VAL_POS_X);
				Value64 += Diff;
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
					EMARCH_ENC_I17_IMM7B_SIZE_X,
					EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM7B_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
					EMARCH_ENC_I17_IMM9D_SIZE_X,
					EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM9D_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
					EMARCH_ENC_I17_IMM5C_SIZE_X,
					EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM5C_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
					EMARCH_ENC_I17_IC_SIZE_X,
					EMARCH_ENC_I17_IC_INST_WORD_POS_X,
					EMARCH_ENC_I17_IC_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
					EMARCH_ENC_I17_IMM41a_SIZE_X,
					EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41a_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
					EMARCH_ENC_I17_IMM41b_SIZE_X,
					EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41b_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
					EMARCH_ENC_I17_IMM41c_SIZE_X,
					EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
					EMARCH_ENC_I17_IMM41c_VAL_POS_X);
				INS_IMM64(Value64,
					((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
					EMARCH_ENC_I17_SIGN_SIZE_X,
					EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
					EMARCH_ENC_I17_SIGN_VAL_POS_X);
				break;
			}
			case IMAGE_REL_BASED_DIR64:
			{
				*(ULONGLONG UNALIGNED *)FixupVA += Diff;
				break;
			}
			case IMAGE_REL_BASED_MIPS_JMPADDR:
			{
				Temp = (*(PULONG)FixupVA & 0x3ffffff) & 2;
				Temp += (ULONG)Diff;
				*(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) | ((Temp >> 2) & 0x3ffffff);
				break;
			}
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				return (PIMAGE_BASE_RELOCATION)NULL;
			}
			++NextOffset;
		}
		return (PIMAGE_BASE_RELOCATION)NextOffset;
	}

	bool ScanHook::IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva)
	{
		WORD SectionNum;
		PIMAGE_SECTION_HEADER Section;
		SectionNum = PeHead->FileHeader.NumberOfSections;
		Section = IMAGE_FIRST_SECTION(PeHead);
		for (int i = 0; i < SectionNum; ++i)
		{
			if ((Section->VirtualAddress <= Rva) && (Rva < (Section->SizeOfRawData + Section->VirtualAddress)))
				return 0;
			++Section;
		}
		return 1;
	}

	bool ScanHook::ParsePe(DWORD ImageBase, PPE_INFO Pe)
	{
		bool ret = 0;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_OPTIONAL_HEADER OpitionHead;
		if (ImageBase)
		{
			DosHead = (PIMAGE_DOS_HEADER)ImageBase;
			if (DosHead->e_magic ==IMAGE_DOS_SIGNATURE)
			{
				Pe->PeHead = (PIMAGE_NT_HEADERS)(ImageBase + DosHead->e_lfanew);
				if (Pe->PeHead->Signature == IMAGE_NT_SIGNATURE)
				{
					OpitionHead = &(Pe->PeHead->OptionalHeader);
					Pe->ExportTableRva = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					Pe->ExportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					Pe->ImportTableRva = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
					Pe->ImportSize = OpitionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
					ret = 1;
				}
			}
		}
		return ret;
	}

	DWORD ScanHook::GetExportByOrdinal(DWORD ImageBase, WORD Ordinal)
	{
		DWORD ApiAddress = 0;
		DWORD *Eat;
		PE_INFO Pe;
		PIMAGE_EXPORT_DIRECTORY ExportTable;
		ParsePe(ImageBase, &Pe);
		if (Pe.ExportSize)
		{
			ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + Pe.ExportTableRva);
			Eat = (DWORD *)(ImageBase + ExportTable->AddressOfFunctions);
			ApiAddress = ((Eat[Ordinal - ExportTable->Base] != 0) ? (ImageBase + Eat[Ordinal - ExportTable->Base]) : 0);
			if ((ApiAddress >= (DWORD)ExportTable) && (ApiAddress < ((DWORD)ExportTable + Pe.ExportSize)))
			{
				ApiAddress = FileNameRedirection((char *)ApiAddress);
				m_IsFromIat = 1;
			}
		}
		return ApiAddress;
	}

	DWORD ScanHook::GetExportByName(DWORD ImageBase, char *ProcName)
	{
		int cmp;
		char *ApiName;
		DWORD ApiAddress = 0;
		WORD Ordinal, *NameOrd;
		DWORD *Ent, *Eat, HigthIndex, LowIndex = 0, MidIndex;
		PE_INFO Pe;
		PIMAGE_EXPORT_DIRECTORY ExportTable;
		ParsePe(ImageBase, &Pe);
		if (Pe.ExportSize)
		{
			ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + Pe.ExportTableRva);
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
				if (ApiAddress >= (DWORD)ExportTable && (ApiAddress < ((DWORD)ExportTable + Pe.ExportSize)))
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

	DWORD ScanHook::FileNameRedirection( char *RedirectionName)
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

	bool ScanHook::ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName, DWORD Size)
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

	bool ScanHook::GetModuleInfomation(WCHAR *DllName, vector<MODULE_INFO>::iterator &iter)
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

	bool ScanHook::GetModuleInfomation(DWORD Address, vector<MODULE_INFO>::iterator &iter)
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

	void ScanHook::GetModulePath(DWORD Address, WCHAR *ModulePath)
	{
		vector<MODULE_INFO>::iterator iter;
		for (iter = ModuleInfo.begin(); iter != ModuleInfo.end(); ++iter)
		{
			if (iter->DllBase == Address)
				wcscpy_s(ModulePath, 260, iter->FullName);
		}
	}

	void ScanHook::GetModulePathByAddress(DWORD Address, WCHAR *ModulePath)
	{
		Address = FindDosHeadInMemory(Address);
		if (Address)
			GetModulePath(Address, ModulePath);
	}

	DWORD ScanHook::FindDosHeadInMemory(DWORD Address)
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