#include "ntapi.hpp"
#include "otherapi.hpp"

#define TEST2
int wmain(int argc, wchar_t* argv[])
{
	PEB Peb = { 0 };
	NTSTATUS Status = 0;
	PROCESS_BASIC_INFORMATION BasicInfo = { 0 };
	STARTUPINFOEXW StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };
	SIZE_T AttributeListLength = 0;//sizeof(PROC_THREAD_ATTRIBUTE_LIST)
	PROC_THREAD_BNOISOLATION_ATTRIBUTE BnoIsolation = { 0 };
	BOOL IgnoreAttributeList = (argc >= 3);
	RtlSecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));
	LPWSTR cmd = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH);
	WCHAR WideString[] = L"   🖥️☁🚬🚬🚬🗿888🎱🎱🎱😢😭😭😭 |*~`!@#$%^& ℃どはばねでびぷ*|  \"'{[🤣👉🤡👈🗿]}'\";/1.1.1.1:1337 \"|<🚀>|\"   ";

	if (argc < 2 && cmd)
	{
		memcpy_s(cmd, 24, L"notepad.exe", 24);
	}
	else if(argv[1] && *argv[1])
	{
		cmd = argv[1];
	}
	else
	{
		return argc;
	}
	//
	// wchar_t cmd[] = L"notepad";
	// wchar_t cmd2[] = L"C:\\Users\\Administrator\\Downloads\\IPPLUS\\IPPLUS.EXE";
	// process.cpp
	//

	BnoIsolation.IsolationEnabled = TRUE;
	RtlMoveMemory(&BnoIsolation.IsolationPrefix, WideString, sizeof(WCHAR) * (3 + lstrlenW(WideString)));
	InitializeProcThreadAttributeList(NULL, 2, 0, &AttributeListLength);

	StartupInfo.StartupInfo.cb = IgnoreAttributeList ? sizeof(STARTUPINFOW) : sizeof(STARTUPINFOEXW);
	StartupInfo.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, AttributeListLength));
	if (!StartupInfo.lpAttributeList)
		return -1;

	if (!InitializeProcThreadAttributeList(StartupInfo.lpAttributeList, 2, 0, &AttributeListLength))
	{
		wprintf(L"InitializeProcThreadAttributeList Fail: %ld\n", GetLastError());
	}
	
	if (!UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_BNO_ISOLATION, &BnoIsolation, sizeof(BnoIsolation), NULL, NULL))
	{
		wprintf(L"UpdateProcThreadAttribute Fail: %ld\n", GetLastError());
	}

	// PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
	// Forces image load preference to prioritize the Windows install System32
	// folder before dll load dir, application dir and any user dirs set.
	// - Affects IAT resolution standard search path only, NOT direct LoadLibrary or
	//   executable search path.

	DWORD64 PolicyFlags[2] = { 0 };
	// | PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
	PolicyFlags[0] = PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
	PolicyFlags[1] = PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION_ALWAYS_ON | PROCESS_CREATION_MITIGATION_POLICY2_SPECULATIVE_STORE_BYPASS_DISABLE_ALWAYS_ON;

	UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &PolicyFlags, sizeof(PolicyFlags), NULL, NULL);
	
#ifndef TEST

	BOOL BoolStatus = CreateProcessInternalW(
		NULL,
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		IgnoreAttributeList ? 0 :EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFOW)&StartupInfo,
		&ProcessInformation,
		NULL);

#else

	BOOL BoolStatus = CreateProcessW(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		IgnoreAttributeList ? 0 : EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		(LPSTARTUPINFOW)&StartupInfo,
		&ProcessInformation);

#endif 
	
	wprintf(L"CreateProcessInternalW: %ls\n", BoolStatus ? L"Success" : L"Fail");
	wprintf(L"Last Win32Error: %ld\n", NtCurrentTeb()->LastErrorValue);
	wprintf(L"Last NtstatusError: 0x%08lx\n", NtCurrentTeb()->LastStatusValue);

	if (ProcessInformation.hProcess)
	{
		wprintf(L"hProcess: 0x%p, PID = %ld\n", ProcessInformation.hProcess, ProcessInformation.dwProcessId);
		wprintf(L"hThread: 0x%p, TID = %ld\n", ProcessInformation.hThread, ProcessInformation.dwThreadId);
		Status = NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(Status))
			return Status;

		Status = NtReadVirtualMemory(ProcessInformation.hProcess, BasicInfo.PebBaseAddress, &Peb, sizeof(Peb), NULL);
		if (!NT_SUCCESS(Status))
			return Status;

		wprintf(L"Peb.SystemDefaultActivationContextData: 0x%p\n", Peb.SystemDefaultActivationContextData);
		wprintf(L"Peb.ActivationContextData:              0x%p\n", Peb.ActivationContextData);
		wprintf(L"=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
		NtWaitForSingleObject(ProcessInformation.hProcess, FALSE, NULL);

		Status = NtQueryInformationProcess(ProcessInformation.hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		wprintf(L"Process %lld Exited: 0x%08lx\n", (ULONGLONG)BasicInfo.UniqueProcessId, BasicInfo.ExitStatus);

		NtClose(ProcessInformation.hProcess);
		NtClose(ProcessInformation.hThread);
	}

	return 0;
}