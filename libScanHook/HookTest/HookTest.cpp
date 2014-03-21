#include "HookTest.h"

pfnMessageBoxW OldMessageBoxW;


int WINAPI MyMessageBoxW(HWND hWnd, PCWSTR pszText, PCWSTR pszCaption, UINT uType)
{
	return 0;
}

int WINAPI fakeMessageBoxW(HWND hWnd, PCWSTR pszText, PCWSTR pszCaption, UINT uType)
{
	if (!wcscmp(pszText, L"test"))
		return OldMessageBoxW(hWnd, L"i'am InlineHook", pszCaption, uType);
	return OldMessageBoxW(hWnd, pszText, pszCaption, uType);
}

void TestHook()
{
	PVOID ptrMessageBoxW;
	CAPIHook("user32.dll", "MessageBoxW", (PROC)MyMessageBoxW);
	ptrMessageBoxW = GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW");
	InstallInlineHook(ptrMessageBoxW, fakeMessageBoxW, (void **)&OldMessageBoxW);
	MessageBoxW(0, L"test", L"test", MB_OK);
}

