#include "ntapi.hpp"
#include "otherapi.hpp"
#include "csrss.hpp"
#include <ntstatus.h>
#include <strsafe.h>

#define WIN32_NO_STATUS
int wmain(int argc, wchar_t* argv[])
{
	PEB Peb = { 0 };
	PROCESS_BASIC_INFORMATION mesInfos = { 0 };
	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
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

	//wchar_t cmd[] = L"notepad";
	//wchar_t cmd[] = L"C:\\Users\\Administrator\\Downloads\\IPPLUS\\IPPLUS.EXE";
	//wprintf(L"[*] OFFSET: %d\n", FIELD_OFFSET(BASE_SXS_CREATEPROCESS_MSG, ApplicationUserModelId));
	//WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];
	//sizeof(ApplicationUserModelId);
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

	if (ProcessInformation.hProcess)
	{
		wprintf(L"hProcess: 0x%p, PID = %d\n", ProcessInformation.hProcess, ProcessInformation.dwProcessId);
		wprintf(L"hThread: 0x%p, TID = %d\n", ProcessInformation.hThread, ProcessInformation.dwThreadId);
		wprintf(L"NtQueryInformationProcess: 0x%08x\n", NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &mesInfos, sizeof(PROCESS_BASIC_INFORMATION), NULL));
		wprintf(L"NtReadVirtualMemory PebBaseAddress: 0x%08x\n", NtReadVirtualMemory(ProcessInformation.hProcess, mesInfos.PebBaseAddress, &Peb, sizeof(Peb), NULL));
		wprintf(L"Peb.SystemDefaultActivationContextData 0x%p\n", Peb.SystemDefaultActivationContextData);
		wprintf(L"Peb.ActivationContextData 0x%p\n", Peb.ActivationContextData);
		wprintf(L"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
		NtWaitForSingleObject(ProcessInformation.hProcess, FALSE, NULL);
		wprintf(L"Process Exited!\n");
	}

	return 0;
}
