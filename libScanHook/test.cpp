// libScanHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include<iostream>
#include "libScanHook.h"
using namespace std;
using namespace libScanHook;

int _tmain(int argc, _TCHAR* argv[])
{
	ScanHook Scan;
	PROCESS_HOOK_INFO HookInfo;
	if (Scan.InitScan(GetCurrentProcessId()))
	{
		while (Scan.GetProcessHookInfo(&HookInfo))
		{
			cout << HookInfo.HookType << endl;
			cout << hex << HookInfo.OriginalAddress << endl;
			cout << hex << HookInfo.HookAddress << endl;
			wcout << HookInfo.HookedApiName << endl;
			wcout << HookInfo.HookedModule << endl;
			wcout << HookInfo.HookLocation << endl;
			cout << endl;
		}
	}
	Scan.CloseScan();
	system("pause");
	return 0;
}

