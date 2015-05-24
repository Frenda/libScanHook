#include "apisetschema.h"

namespace apisetschema
{
	ApiSet::ApiSet()
	{
		Init();
	}

	ApiSet::~ApiSet()
	{
		if (m_Buffer)
			delete[] m_Buffer;
	}

	void ApiSet::Init()
	{
		WCHAR SysPath[260];
		HANDLE hFile;
		DWORD Size;
		PIMAGE_DOS_HEADER DosHead;
		PIMAGE_NT_HEADERS NtHead;
		PIMAGE_SECTION_HEADER SectionHead;
		m_Version = 0;
		if (GetSystemDirectoryW(SysPath, 260) != 0)
		{
			wcscat_s(SysPath, L"\\apisetschema.dll");
			hFile = CreateFileW(SysPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				Size = GetFileSize(hFile, 0);
				m_Buffer = new BYTE[Size];
				if (ReadFile(hFile, m_Buffer, Size, 0, 0))
				{
					DosHead = (PIMAGE_DOS_HEADER)m_Buffer;
					NtHead = (PIMAGE_NT_HEADERS)((DWORD)DosHead + DosHead->e_lfanew);
					SectionHead = IMAGE_FIRST_SECTION(NtHead);
					//apisetschema.dll第一个区段就是储存apisetschema的信息的
					m_ApiSetHead = m_Buffer + SectionHead->PointerToRawData;
					m_Version = *(DWORD *)m_ApiSetHead;
				}
				CloseHandle(hFile);
			}
		}
	}

	bool ApiSet::GetRealDll(WCHAR *ApiSetName, WCHAR *DllBaseName, WCHAR *RealName, DWORD Size, bool IsEat)
	{
		bool ret = 0;
		WCHAR *NameBuffer, *ptr;
		WCHAR LibName[64];
		DWORD LibNameSize, HostNameSize;
		PAPI_SET_NAMESPACE_ARRAY_V2 SetMapHead_v2;
		PAPI_SET_VALUE_ARRAY_V2 SetMapHost_v2;
		PAPI_SET_NAMESPACE_ARRAY_V4 SetMapHead_v4;
		PAPI_SET_VALUE_ARRAY_V4 SetMapHost_v4;
		ptr = wcschr(ApiSetName, L'.');
		if (ptr)
			*ptr = 0;
		if (m_Version)
		{
			switch (m_Version)
			{
			case 2:
			{
				SetMapHead_v2 = (PAPI_SET_NAMESPACE_ARRAY_V2)m_ApiSetHead;
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
							if (!_wcsnicmp(DllBaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsEat)
							{
								HostNameSize = SetMapHost_v2->Entry[1].ValueLength;
								NameBuffer = (WCHAR *)((DWORD)SetMapHead_v2 + SetMapHost_v2->Entry[1].ValueOffset);
							}
						}
						wcsncpy_s(RealName, Size, NameBuffer, HostNameSize / sizeof(WCHAR));
						ret = 1;
						break;
					}
				}
			}
			case 4:
			{
				SetMapHead_v4 = (PAPI_SET_NAMESPACE_ARRAY_V4)m_ApiSetHead;
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
							if (!_wcsnicmp(DllBaseName, NameBuffer, HostNameSize / sizeof(WCHAR)) || IsEat)
							{
								HostNameSize = SetMapHost_v4->Entry[1].ValueLength;
								NameBuffer = (WCHAR *)((DWORD)SetMapHead_v4 + SetMapHost_v4->Entry[1].ValueOffset);
							}
						}
						wcsncpy_s(RealName, Size, NameBuffer, HostNameSize / sizeof(WCHAR));
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
}