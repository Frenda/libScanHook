// libScanHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include<iostream>
#include<iomanip>
#include "libScanHook.h"
using namespace std;
using namespace libscanhook;

int _tmain(int argc, _TCHAR* argv[])
{
	SCANHOOK Scan;
	PROCESS_HOOK_INFO HookInfo;
	DWORD Pid;
	cout << "输入PID: ";
	cin >> Pid;
	if (Scan.InitScan(Pid))
	{
		while (Scan.GetProcessHookInfo(&HookInfo))
		{
			cout << "钩子类型: ";
			switch (HookInfo.HookType)
			{
			case EatHook:
				cout << "EatHook" << endl;
				break;
			case IatHook:
				cout << "IatHook" << endl;
				break;
			case InlineHook:
				cout << "InlineHook" << endl;
				break;
			default:
				break;
			}
			cout << "原函数的地址: 0x" << setw(8) << setfill('0') << hex << HookInfo.OriginalAddress << endl;
			cout << "钩子的地址: 0x" << setw(8) << setfill('0') << hex << HookInfo.HookAddress << endl;
			cout << "被挂钩的函数名: ";
			wcout << HookInfo.HookedApiName << endl;
			cout << "被挂钩的模块名: ";
			wcout << HookInfo.HookedModule << endl;
			cout << "钩子所在的模块: ";
			wcout << HookInfo.HookLocation << endl;
			cout << endl;
		}
	}
	system("pause");
	return 0;
}

