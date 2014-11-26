#pragma once

#include<Windows.h>

namespace libpe
{

	typedef struct _PE_INFO
	{
		PIMAGE_NT_HEADERS PeHead;
		DWORD ExportTableRva;
		DWORD ExportSize;
		DWORD ImportTableRva;
		DWORD ImportSize;
	} PE_INFO, *PPE_INFO;

	class LIBPE
	{
	public:
		bool Parse(DWORD ImageBase, PPE_INFO Pe);
		bool IsGlobalVar(PIMAGE_NT_HEADERS PeHead, DWORD Rva);
	};
}