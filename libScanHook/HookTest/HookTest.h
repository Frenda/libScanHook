#pragma once

#include<Windows.h>
#include "APIHook.h"
#include "inlinehook.h"

int WINAPI MyMessageBoxW(HWND hWnd, PCWSTR pszText, PCWSTR pszCaption, UINT uType);

typedef int (WINAPI *pfnMessageBoxW)(HWND hWnd, PCWSTR pszText, PCWSTR pszCaption, UINT uType);

int WINAPI fakeMessageBoxW(HWND hWnd, PCWSTR pszText, PCWSTR pszCaption, UINT uType);

void TestHook();
