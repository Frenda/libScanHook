#pragma once

#include<Windows.h>
#include "ntdll.h"
#include "libPe.h"
using namespace libpe;

namespace peloader
{
	class PELOADER
	{
	public:
		bool Loader(WCHAR *FilePath, DWORD DllBase, void *Buffer, DWORD BufferSize);

	private:
		UINT AlignSize(UINT Size, UINT Align);
		bool FixBaseRelocTable(DWORD NewImageBase, DWORD ExistImageBase);
		PIMAGE_BASE_RELOCATION ProcessRelocationBlock(ULONG_PTR VA, ULONG SizeOfBlock, PUSHORT NextOffset, LONGLONG Diff);
	};
}