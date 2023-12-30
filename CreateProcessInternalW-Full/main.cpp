#include "ntapi.hpp"
#include "otherapi.hpp"
//#include "csrss.hpp"
#include <strsafe.h>

// #define TEST
int wmain(int argc, wchar_t* argv[])
{
	PEB Peb = { 0 };
	PROCESS_BASIC_INFORMATION BasicInfo = { 0 };
	ACTIVATION_CONTEXT_DATA ActivationContextData = { 0 };
	STARTUPINFOEXW StartupInfo = { sizeof(StartupInfo) };
	PROCESS_INFORMATION ProcessInformation = { 0 };
	RtlSecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));
	LPWSTR cmd = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH);

	if (argc != 2 && cmd)
	{
		memcpy_s(cmd, 24, L"notepad.exe", 24);
	}
	else if(argv[1] && *argv[1])
	{
		cmd = argv[1];
	}
	
	//
	// wchar_t cmd[] = L"notepad";
	// wchar_t cmd[] = L"C:\\Users\\Administrator\\Downloads\\IPPLUS\\IPPLUS.EXE";
	// wprintf(L"[*] OFFSET: %d\n", FIELD_OFFSET(BASE_SXS_CREATEPROCESS_MSG, ApplicationUserModelId));
	// WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH]; //sizeof(ApplicationUserModelId);
	// process.cpp
	//
	//PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT

	WCHAR WideString[] = L"I-am-BNO-in-BaseNamedObjects";
	SIZE_T attributeListLength = 0;//sizeof(PROC_THREAD_ATTRIBUTE_LIST)
	PROC_THREAD_BNOISOLATION_ATTRIBUTE bnoIsolation = { 0 };
	bnoIsolation.IsolationEnabled = TRUE;
	RtlMoveMemory(&bnoIsolation.IsolationPrefix, WideString, sizeof(WideString) - sizeof(UNICODE_NULL));


	InitializeProcThreadAttributeList(NULL, 2, 0, &attributeListLength);//

	StartupInfo.StartupInfo.cb = sizeof(StartupInfo);
	StartupInfo.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attributeListLength));
	if (!StartupInfo.lpAttributeList)
		return -1;
	if (!InitializeProcThreadAttributeList(StartupInfo.lpAttributeList, 2, 0, &attributeListLength))
	{
		wprintf(L"InitializeProcThreadAttributeList Fail: %ld\n", GetLastError());
	}
	
	if (!UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_BNO_ISOLATION, &bnoIsolation, sizeof bnoIsolation, nullptr, nullptr))
	{
		wprintf(L"UpdateProcThreadAttribute Fail: %ld\n", GetLastError());
	}
	// PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
	// Forces image load preference to prioritize the Windows install System32
	// folder before dll load dir, application dir and any user dirs set.
	// - Affects IAT resolution standard search path only, NOT direct LoadLibrary or
	//   executable search path.
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
		// | PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;

	UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

#ifndef TEST

	BOOL BoolStatus = CreateProcessInternalW(
		NULL,
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFOW)&StartupInfo,
		&ProcessInformation,
		NULL
	);
	
	
#else
	BOOL BoolStatus = CreateProcessW(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFOW)&StartupInfo,
		&ProcessInformation
	);
#endif 
	wprintf(L"CreateProcessInternalW: %ls\n", BoolStatus ? L"Success" : L"Fail");
	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);
	if (ProcessInformation.hProcess)
	{
		wprintf(L"hProcess: 0x%p, PID = %ld\n", ProcessInformation.hProcess, ProcessInformation.dwProcessId);
		wprintf(L"hThread: 0x%p, TID = %ld\n", ProcessInformation.hThread, ProcessInformation.dwThreadId);

		NTSTATUS Status = NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(Status))
		{
			return 2;
		}
		Status = NtReadVirtualMemory(ProcessInformation.hProcess, BasicInfo.PebBaseAddress, &Peb, sizeof(Peb), NULL);
		if (!NT_SUCCESS(Status))
		{
			return 2;
		}
		wprintf(L"Peb.SystemDefaultActivationContextData 0x%p\n", Peb.SystemDefaultActivationContextData);
		wprintf(L"Peb.ActivationContextData 0x%p\n", Peb.ActivationContextData);
		wprintf(L"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
		NtWaitForSingleObject(ProcessInformation.hProcess, FALSE, NULL);
		Status = NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		wprintf(L"Process Exited: 0x%08lx\n", BasicInfo.ExitStatus);
		NtClose(ProcessInformation.hProcess);
		NtClose(ProcessInformation.hThread);
	}
	
	return 0;
}

