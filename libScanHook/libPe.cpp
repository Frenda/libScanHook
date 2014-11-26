#include "libPe.h"

namespace libpe
{
	bool LIBPE::Parse(DWORD ImageBase, PPE_INFO Pe)
	{
		bool ret = 0;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_OPTIONAL_HEADER OpitionHead;
		if (ImageBase)
		{
			DosHead = (PIMAGE_DOS_HEADER)ImageBase;
			if (DosHead->e_magic == IMAGE_DOS_SIGNATURE)
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

	bool LIBPE::IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva)
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
}