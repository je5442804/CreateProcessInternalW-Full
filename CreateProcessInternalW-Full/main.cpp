#include "ntapi.hpp"
#include "otherapi.hpp"
#include "csrss.hpp"
#include <ntstatus.h>
#include <strsafe.h>

int wmain(int argc, wchar_t* argv[])
{
	//wprintf(L"CsrServerReadOnlySharedMemoryBase: 0x%llx\n", NtCurrentPeb()->CsrServerReadOnlySharedMemoryBase);
	STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
	PROCESS_INFORMATION ProcessInformation = { 0 };
	RtlSecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));
	LPWSTR cmd = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH);
	if (argv[1] && *argv[1])
		cmd = argv[1];
	else if (cmd != 0)
		memcpy(cmd, L"notepad.exe", 24);
	else
		exit(-1);

	BOOL BoolStatus = CreateProcessInternalW(
		NULL,
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInformation,
		NULL
	);

	wprintf(L"CreateProcessInternalW: %d\n", BoolStatus);
	wprintf(L"Last Win32Error: %d\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08x\n", NtCurrentTeb()->LastStatusValue);
	PEB peb2 = { 0 };
	PROCESS_BASIC_INFORMATION mesInfos = { 0 };
	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
	RTL_USER_PROCESS_PARAMETERS god = { 0 };
	if (ProcessInformation.hProcess)
	{
		wprintf(L"hProcess: 0x%p, PID = %d\n", ProcessInformation.hProcess, ProcessInformation.dwProcessId);
		wprintf(L"hThread: 0x%p, TID = %d\n", ProcessInformation.hThread, ProcessInformation.dwThreadId);
		wprintf(L"NtQueryInformationProcess: 0x%08x\n", NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &mesInfos, sizeof(PROCESS_BASIC_INFORMATION), NULL));
		wprintf(L"PEB2Address NtReadVirtualMemory: 0x%08x\n", NtReadVirtualMemory(ProcessInformation.hProcess, mesInfos.PebBaseAddress, &peb2, sizeof(peb2), NULL));
		wprintf(L"peb2.SystemDefaultActivationContextData 0x%p\n", peb2.SystemDefaultActivationContextData);
		wprintf(L"peb2.ActivationContextData 0x%p\n", peb2.ActivationContextData);
		wprintf(L"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
		WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
	}
	
	wprintf(L"Done!\n");
	return 0;
}
