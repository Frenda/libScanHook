#include "PeLoader.h"

namespace peloader
{
	bool PELOADER::Loader(WCHAR *FilePath, DWORD DllBase, void *Buffer, DWORD BufferSize)
	{
		bool ret = 0;
		void *FileBuffer;
		DWORD SectionNum, HeaderSize, DateSize, FileAlignment, SectionAlignment, i;
		HANDLE hFile;
		LIBPE Pe;
		PE_INFO PeInfo;
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
						Pe.Parse((DWORD)FileBuffer, &PeInfo);
						SectionHead = IMAGE_FIRST_SECTION(PeInfo.PeHead);
						SectionNum = PeInfo.PeHead->FileHeader.NumberOfSections;
						HeaderSize = PeInfo.PeHead->OptionalHeader.SizeOfHeaders;
						FileAlignment = PeInfo.PeHead->OptionalHeader.FileAlignment;
						SectionAlignment = PeInfo.PeHead->OptionalHeader.SectionAlignment;
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

	UINT PELOADER::AlignSize(UINT Size, UINT Align)
	{
		return ((Size + Align - 1) / Align * Align);
	}

	bool PELOADER::FixBaseRelocTable(DWORD NewImageBase, DWORD ExistImageBase)
	{
		LONGLONG Diff;
		ULONG TotalCountBytes, SizeOfBlock;
		ULONG_PTR VA;
		ULONGLONG OriginalImageBase;
		PUSHORT NextOffset = 0;
		LIBPE Pe;
		PE_INFO PeInfo;
		PIMAGE_BASE_RELOCATION NextBlock;
		Pe.Parse(NewImageBase, &PeInfo);
		if (PeInfo.PeHead == 0)
			return 0;
		switch (PeInfo.PeHead->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS32)PeInfo.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			OriginalImageBase = ((PIMAGE_NT_HEADERS64)PeInfo.PeHead)->OptionalHeader.ImageBase;
			break;
		}
		default:
			return 0;
		}
		NextBlock = (PIMAGE_BASE_RELOCATION)(NewImageBase +
			PeInfo.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		TotalCountBytes = PeInfo.PeHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (!NextBlock || !TotalCountBytes)
		{
			if (PeInfo.PeHead->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
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

	PIMAGE_BASE_RELOCATION PELOADER::ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff)
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
}