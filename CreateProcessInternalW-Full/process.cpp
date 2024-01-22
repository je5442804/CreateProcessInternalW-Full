#include <strsafe.h>
#include "ntapi.hpp"
#include "otherapi.hpp"
#include "csrss.hpp"
#include "syscalls.hpp"

BOOL WINAPI CreateProcessInternalW(
	HANDLE hUserToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	OPTIONAL PHANDLE hRestrictedUserToken //NULL
)
{
	//RtlGetDeviceFamilyInfoEnum_ RtlGetDeviceFamilyInfoEnum = (RtlGetDeviceFamilyInfoEnum_)GetProcAddress(Ntdll, "RtlGetDeviceFamilyInfoEnum");
	//unresolved external symbol ... **** *** **
	init();
	
	BOOL bStatus = FALSE;
	NTSTATUS Status = 0;
	NTSTATUS AliasStatus = 0;
	NTSTATUS SaferStatus = 0;
	LONG Win32Error = 0;
	CHAR PriorityClass = 0;
	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;
	HANDLE DebugPortHandle = NULL;
	PS_PROTECTION Protection = { 0 };
	BOOLEAN AppXProtectEnabled = FALSE;
	PS_TRUSTLET_CREATE_ATTRIBUTES TrustletAttributes = { 0 };
	PS_CREATE_INFO CreateInfo = { 0 };
	PS_ATTRIBUTE_LIST AttributeList = { 0 };
	PS_ATTRIBUTE_LIST AttributeListTemp = { 0 };
	ULONG AttributeListCount = 0;
	ULONG AttributeListTempCount = 0;
	
	ULONG DefaultErrorMode = 0;
	BOOLEAN ChpeOption = FALSE;
	SECTION_IMAGE_INFORMATION SectionImageInfomation = { 0 };
	UNICODE_STRING NtImagePath = { 0 };
	UNICODE_STRING Win32ImagePath = { 0 };
	UNICODE_STRING CommandLine = { 0 };
	UNICODE_STRING PackageFullName = { 0 };
	HANDLE ParentProcessHandle = NULL;
	ULONG ProcessFlags = 0;
	CLIENT_ID ClientId = { 0 };

	PVOID ManifestAddress = 0;
	ULONG ManifestSize = 0;
	PPEB PebAddressNative = 0;
	USHORT CurrentProcessMachine = 0;
	USHORT TargetProcessMachine = 0;
	HANDLE TokenHandle = NULL;
	HANDLE SaveImpersonateTokenHandle = NULL;
	HANDLE CurrentTokenHandle = NULL;
	HANDLE LowBoxToken = NULL;
	HANDLE AppAliasTokenHandle = NULL;
	ULONG CurrentTokenSessionId = 0;
	ULONG Length = 0;
	SIZE_T RegionSize = 0;;
	RTL_PATH_TYPE PathType = RtlPathTypeUnknown;

	PSECURITY_CAPABILITIES SecurityCapabilities = 0;
	LPVOID UnicodeEnvironment = 0;

	LPSTARTUPINFOEXW ExtendStartupInfo = NULL;
	STARTUPINFOW StartupInfo = { 0 };

	LPWSTR FilePart = 0;
	LPWSTR CurrentDirectoryHeap = NULL;
	DWORD FullPathNameLength = 0;
	OBJECT_ATTRIBUTES LocalProcessObjectAttribute = { 0 };
	OBJECT_ATTRIBUTES LocalThreadObjectAttribute = { 0 };
	POBJECT_ATTRIBUTES ProcessObjectAttributes = { 0 };
	POBJECT_ATTRIBUTES ThreadObjectAttributes = { 0 };
	BOOL DefaultInheritOnly = FALSE;

	ACTIVATION_TOKEN_INFO ActivationTokenInfo = { 0 };
	HANDLE ActivationToken = NULL;//兼容
	HANDLE AppXPackageImpersonateToken = NULL;

	PWSTR ExePathFullBuffer = NULL;
	LPWSTR QuotedCmdLine = NULL;
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	HANDLE LowBoxTokenHandle = NULL;
	PVOID AppCompatData = NULL;
	DWORD AppCompatDataSize = 0;
	PVOID AppCompatSxsData = NULL;
	DWORD AppCompatSxsDataSize = 0;
	PSDBQUERYRESULT SdbQueryResult = NULL;// PVOID
	DWORD SdbQueryResultSize = 0;
	ULONG dwFusionFlags = 0;
	COAMPAT_FIX_FLAG dwLuaRunlevelFlags = { 0 };
	DWORD dwInstallerFlags = 0;
	DWORD ElevationFlags = 0;

	USHORT AppCompatImageMachine = 0;
	DWORD DeviceFamilyID = 0;

	HANDLE VdmWaitHandle = NULL;
	ANSI_STRING AnsiStringVDMEnv = { 0 };
	UNICODE_STRING UnicodeStringVDMEnv = { 0 };
	ULONG VdmCreationState = 0;
	ULONG VdmBinaryType = 0;
	ULONG VdmTaskId = 0;
	BOOL VdmPartiallyCreated = FALSE;
	BOOLEAN bSaferChecksNeeded = FALSE;
	BOOLEAN AlreadyQueryImageFileDebugger = FALSE;
	PWSTR ImageFileDebuggerCommand = NULL;
	//BOOL AppAliasRedirect = FALSE;

	ExtendedPackagedAppContext::ExtendedPackagedAppContext* lpExtendedPackagedAppContext = NULL;

	HANDLE IFEOKey = NULL;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = { 0 };
	ULONG ExtendedFlags = 0;
	BOOLEAN HasHandleList = FALSE;
	CONSOLE_REFERENCE ConsoleHandleInfo = { 0 };
	PS_MITIGATION_OPTIONS_MAP MitigationOptions = { 0 };
	PS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptions = { 0 };
	WIN32K_SYSCALL_FILTER Win32kFilter = { 0 };
	ULONG AllApplicationPackagesPolicy  = 0;
	ULONG ComponentFilter = 0;
	MAXVERSIONTESTED_INFO MaxVersionTested = { 0 };
	PS_BNO_ISOLATION_PARAMETERS BnoIsolation = { 0 };
	DWORD DesktopAppPolicy = 0;
	ISOLATION_MANIFEST_PROPERTIES IsolationManifest = { 0 };
	UNICODE_STRING UnknowStringProcThread20 = { 0 };
	ULONG_PTR UnknowULONG_PTRProcThread21 = NULL;
	BOOLEAN PackageNameSpecified = FALSE;
	BOOL IsolationEnabled = FALSE;
	BOOL GetMitigationPolicySuccess = FALSE;
	PS_STD_HANDLE_INFO StdHandle = { 0 };
	USHORT DosPathLength = 0;
	BOOL ThreadTokenImpersonated = FALSE;
	BOOL ImpersonateRebackSuccess = FALSE;
	BOOL IsImageValidFixed = FALSE;
	BOOL IsBatchFile = FALSE;
	BOOL ImageVersionOk = FALSE;
	PIMAGE_NT_HEADERS CurrentImageHeaders = { 0 };
	WCHAR packageFullName[128] = { 0 };

	PVOID AppXEnvironment = 0;
	PAPPX_PROCESS_CONTEXT AppXContent = 0;
	PAPPX_PROCESS_CONTEXT AppXProcessContext = 0;
	HANDLE AppXTokenHandle = NULL;
	
	BOOL AppXPackageBnoIsolationDetected = FALSE;
	DWORD AppModelPolicyValue = 0;
	ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo = 0;
	PS_PKG_CLAIM PackageClaims = { 0 };
	ULONG_PTR AttributesPresent = 0;
	BOOL AppXPackageBreakaway = 0;
	BOOL BypassAppxExtension = 0;

	UNICODE_STRING SubSysCommandLine = { 0 };

	SIZE_T PackageCommandLineLength = 0;
	LPCWSTR PackageCommandLineLink = NULL;
	PWSTR PackageNewCommandLine = NULL;
	BOOL AlreadyGetPackagedAppInfo = FALSE;
	ULONG ActivationFlag = 0;// Unknow
	//DWORD UnknowActivationSxsFlags = 0;
	PVOID AppXEnvironmentExtension = 0;
	PWSTR NameBuffer = NULL;
	ULONG LastErrorValue = NULL;
	WCHAR TempChar = 0;
	LPWSTR TempNull = 0;
	LPWSTR WhiteScan = 0;

	ULONG ReturnedLength = 0;
	STRSAFE_LPWSTR  QuotedBuffer = 0;
	SIZE_T QuotedBufferLength = 0;
	BOOLEAN QuoteInsert = FALSE;
	BOOLEAN QuoteCmdLine = FALSE;
	BOOLEAN QuoteFound = FALSE;
	BOOLEAN SearchRetry = FALSE;
	BOOLEAN IsWowBinary = FALSE;
	LPWSTR NewCommandLine = NULL;

	ULONG CaptureStringsCount = 0;
	LPWSTR PathToSearch = 0;
	USHORT ImageProcessorArchitecture = 0;
	PCSR_CAPTURE_BUFFER CaptureBuffer = 0;
	SXS_CREATEPROCESS_UTILITY SxsCreateProcessUtilityStruct = { 0 };

	BASE_API_MSG ApiMessage = { 0 };
	PBASE_CREATEPROCESS_MSG BaseCreateProcessMessage = &ApiMessage.u.BaseCreateProcess;
	PUNICODE_STRING CsrStringsToCapture[6] = { 0 };
	//ULONG DataLength = 0;
	//SIZE_T TotalLength = 0;

	SubSysCommandLine.Buffer = NULL;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	LPWSTR AppXAliasCommandline = 0;

	ExtendStartupInfo = (LPSTARTUPINFOEXW)lpStartupInfo;

	TokenHandle = hUserToken;
	AnsiStringVDMEnv.Buffer = NULL;
	UnicodeStringVDMEnv.Buffer = NULL;
	memset(&MitigationOptions, 0, sizeof(MitigationOptions));
	memset(&MitigationAuditOptions, 0, sizeof(MitigationAuditOptions));
	memset(&SxsCreateProcessUtilityStruct, 0, sizeof(SxsCreateProcessUtilityStruct));
	memset(packageFullName, 0, sizeof(packageFullName));
	memset(&IsolationManifest, 0, sizeof(IsolationManifest));

	if (!lpApplicationName && !lpCommandLine)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER_MIX);
		return FALSE;
	}
	if (!lpProcessInformation || !lpStartupInfo)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}
	if ((dwCreationFlags & (DETACHED_PROCESS | CREATE_NEW_CONSOLE)) == (DETACHED_PROCESS | CREATE_NEW_CONSOLE))
	{
		RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if ((dwCreationFlags & CREATE_SEPARATE_WOW_VDM) && (dwCreationFlags & CREATE_SHARED_WOW_VDM))
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);//VDM
		return FALSE;
	}
	else if (!(dwCreationFlags & CREATE_SHARED_WOW_VDM) && BaseStaticServerData->DefaultSeparateVDM)
	{
		dwCreationFlags |= CREATE_SEPARATE_WOW_VDM;
	}
	if (dwCreationFlags & IDLE_PRIORITY_CLASS)
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_IDLE;
	}
	else if (dwCreationFlags & BELOW_NORMAL_PRIORITY_CLASS)
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_BELOW_NORMAL;
	}
	else if (dwCreationFlags & NORMAL_PRIORITY_CLASS)
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_NORMAL;
	}
	else if (dwCreationFlags & ABOVE_NORMAL_PRIORITY_CLASS)
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL;
	}
	else if (dwCreationFlags & HIGH_PRIORITY_CLASS)
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_HIGH;
	}
	else if (dwCreationFlags & REALTIME_PRIORITY_CLASS)
	{
		if (BasepIsRealtimeAllowed(FALSE, hUserToken != NULL))
			PriorityClass = PROCESS_PRIORITY_CLASS_REALTIME;
		else
			PriorityClass = PROCESS_PRIORITY_CLASS_HIGH;
	}
	else
	{
		PriorityClass = PROCESS_PRIORITY_CLASS_UNKNOWN;
	}
	/* Done with the priority masks, so get rid of them */
	dwCreationFlags &= ~PRIORITY_CLASS_MASK;

	if (dwCreationFlags & CREATE_PROTECTED_PROCESS)
	{
		ProcessFlags = PROCESS_CREATE_FLAGS_PROTECTED_PROCESS;
	}
	if (dwCreationFlags & CREATE_BREAKAWAY_FROM_JOB)
	{
		ProcessFlags |= PROCESS_CREATE_FLAGS_BREAKAWAY;
	}
	if (dwCreationFlags & INHERIT_PARENT_AFFINITY)
	{
		ProcessFlags |= PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT;
	}
	if (!(dwCreationFlags & CREATE_SUSPENDED))
	{
		ProcessFlags |= PROCESS_CREATE_FLAGS_SUSPENDED;
	}
	if (dwCreationFlags & (DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS))
	{
		Status = DbgUiConnectToDbg();
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			return FALSE;
		}
		DebugPortHandle = DbgUiGetThreadDebugObject();
		if (dwCreationFlags & DEBUG_ONLY_THIS_PROCESS)
		{
			ProcessFlags |= PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT;
		}
	}
	else
	{
		DebugPortHandle = NULL;
	}

	AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList.Attributes[0].ReturnLength = 0;

	AttributeList.Attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList.Attributes[1].Size = sizeof(CLIENT_ID);
	AttributeList.Attributes[1].ReturnLength = 0;
	AttributeList.Attributes[1].ValuePtr = &ClientId;

	AttributeList.Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
	AttributeList.Attributes[2].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList.Attributes[2].ReturnLength = 0;
	AttributeList.Attributes[2].ValuePtr = &SectionImageInfomation;

	AttributeListCount = 3;
	if (DebugPortHandle)
	{
		AttributeList.Attributes[3].Attribute = PS_ATTRIBUTE_DEBUG_OBJECT;
		AttributeList.Attributes[3].Size = sizeof(HANDLE);
		AttributeList.Attributes[3].ReturnLength = 0;
		AttributeList.Attributes[3].ValuePtr = DebugPortHandle;
		AttributeListCount = 4;
	}
	if (PriorityClass != PROCESS_PRIORITY_CLASS_UNKNOWN)
	{
		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_PRIORITY_CLASS;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(CHAR);
		AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
		AttributeList.Attributes[AttributeListCount].ValuePtr = &PriorityClass;
		AttributeListCount++;
	}
	if (dwCreationFlags & CREATE_DEFAULT_ERROR_MODE)
	{
		DefaultErrorMode = TRUE;
		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_ERROR_MODE;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(ULONG);
		AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
		AttributeList.Attributes[AttributeListCount].ValuePtr = &DefaultErrorMode;
		AttributeListCount++;
	}
	if (dwCreationFlags & CREATE_SECURE_PROCESS)
	{
		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_SECURE_PROCESS;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(ULONGLONG);		//	Trustlet 0 Attributes && 0 Data inside...  nonconstant
		AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
		AttributeList.Attributes[AttributeListCount].ValuePtr = &TrustletAttributes;//  in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD 
	}
	lpProcessInformation->hProcess = NULL;
	lpProcessInformation->hThread = NULL;
	if (lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		Status = RtlCreateEnvironmentEx(lpEnvironment, &UnicodeEnvironment, RTL_CREATE_ENVIRONMENT_TRANSLATE);
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			//_local_unwind SEH?
			BaseSetLastNTError(STATUS_NO_MEMORY);
			bStatus = FALSE;
			goto Leave_Cleanup;

		}
		lpEnvironment = UnicodeEnvironment;
		dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
	}

	
	StartupInfo = ExtendStartupInfo->StartupInfo;
	if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT)
	{
		if (StartupInfo.cb != sizeof(STARTUPINFOEXW))
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		lpAttributeList = ExtendStartupInfo->lpAttributeList;
		if (lpAttributeList)
		{
			// 23->23->25->26->27

			wprintf(L"[!] AttributeListCount: %ld\n", AttributeListCount);
			Status = BasepConvertWin32AttributeList(
				lpAttributeList,
				0,
				&ExtendedFlags,
				&PackageFullName,
				&SecurityCapabilities,
				&HasHandleList,
				&ParentProcessHandle,			// PSEUDOCONSOLE_INHERIT_CURSOR ?
				&ConsoleHandleInfo,				// CONSOLE_HANDLE_INFO   //IN ProcessParameters ?<- CONSOLE_IGNORE_CTRL_C = 0x1// CONSOLE_HANDLE_REFERENCE = 0x2// CONSOLE_USING_PTY_REFERENCE = 0x4
				&MitigationOptions,				// PS_MITIGATION_OPTIONS_MAP 
				&MitigationAuditOptions,		// PS_MITIGATION_AUDIT_OPTIONS_MAP
				&Win32kFilter,					// WIN32K_SYSCALL_FILTER 11
				&AllApplicationPackagesPolicy,	// [微软2023/10 紧急添加 one by one 2023/11]
				&ComponentFilter,				// ULONG ComponentFilter
				&MaxVersionTested,				// MAXVERSIONTESTED_INFO ???
				&BnoIsolation,					// PS_BNO_ISOLATION_PARAMETERS
				&DesktopAppPolicy,				// DWORD (PROCESS_CREATION_DESKTOP_APP_*)
				&IsolationManifest,				// in ISOLATION_MANIFEST_PROPERTIES* // rev (diversenok) // since 19H2+
				&UnknowStringProcThread20,
				&UnknowULONG_PTRProcThread21,
				&TrustletAttributes,			// [win 11 22H2++ >=22600 in PS_TRUSTLET_CREATE_ATTRIBUTES* TrustletType_TrustedApp]
				&ProcessFlags,					// [win 11 才有 >= 22000]
				&AttributeList,
				&AttributeListCount,
				27);							// OPTIONAL ProcThreadAttributeMax Count [Count] 32 - 5Present = 27 AttributeList[Max=32]
			wprintf(L"[!] AttributeListCount: %ld\n", AttributeListCount);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}

			if (lpAttributeList->PresentFlags & ProcThreadAttributePresentFlag(ProcThreadAttributePackageFullName))
			{
				
				PackageNameSpecified = TRUE;
				if (SecurityCapabilities)
				{
					BaseSetLastNTError(STATUS_INVALID_PARAMETER);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}

			if ((lpAttributeList->PresentFlags & ProcThreadAttributePresentFlag(ProcThreadAttributeBnoIsolation)))
			{
				IsolationEnabled = TRUE;
			}
				

			if (ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_FORCE_BREAKAWAY)
				ProcessFlags |= PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY;

			// win 11 newest
			if(lpAttributeList->PresentFlags & ProcThreadAttributePresentFlag(ProcThreadAttributeTrustedApp))
				dwCreationFlags |= CREATE_SECURE_PROCESS;

		}
	}
	if (!(dwCreationFlags & CREATE_SEPARATE_WOW_VDM))
	{
		BOOL IsInJob = FALSE;
		if (IsProcessInJob(ParentProcessHandle ? ParentProcessHandle : NtCurrentProcess(), NULL, &IsInJob) && IsInJob)
			dwCreationFlags = (dwCreationFlags & (~CREATE_SHARED_WOW_VDM)) | CREATE_SEPARATE_WOW_VDM;
	}
	if ((StartupInfo.dwFlags & STARTF_USESTDHANDLES) && StartupInfo.dwFlags & (STARTF_USEHOTKEY | STARTF_HASSHELLDATA))
		StartupInfo.dwFlags &= ~(STARTF_USESTDHANDLES);

	if (lpCurrentDirectory)
	{
		CurrentDirectoryHeap = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH - sizeof(UNICODE_NULL));
		if (!CurrentDirectoryHeap)
		{
			BaseSetLastNTError(STATUS_NO_MEMORY);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		FullPathNameLength = GetFullPathNameW(lpCurrentDirectory, MAX_PATH - 1, CurrentDirectoryHeap, &FilePart);
		if (FullPathNameLength >= MAX_PATH)
		{
			wprintf(L"[*] GetFullPathNameW Status = 0x%08lx\n", Status);
			RtlSetLastWin32Error(ERROR_DIRECTORY);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (!FullPathNameLength)
		{
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		lpCurrentDirectory = CurrentDirectoryHeap;
	}
	
	Status = BaseFormatObjectAttributes(
		&LocalProcessObjectAttribute,
		lpProcessAttributes,
		NULL,
		&ProcessObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] BaseFormatObjectAttributes Status = 0x%08lx\n", Status);
		BaseSetLastNTError(Status);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	Status = BaseFormatObjectAttributes(
		&LocalThreadObjectAttribute,
		lpThreadAttributes,
		NULL,
		&ThreadObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] BaseFormatObjectAttributes Status = 0x%08lx\n", Status);
		BaseSetLastNTError(Status);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	AppAliasTokenHandle = TokenHandle;
	AttributeListTempCount = AttributeListCount;//Saved!
	while (TRUE)
	{
		AttributeListCount = AttributeListTempCount;//Restore!
		DefaultInheritOnly = bInheritHandles && !HasHandleList ? TRUE : FALSE; //if bInheritHandles && !HasHandleList ->  DefaultInheritOnly = TRUE

		AppXTokenHandle = TokenHandle;

		if (lpExtendedPackagedAppContext && lpExtendedPackagedAppContext->Breakaway != TRUE)
		{
			AppXTokenHandle = lpExtendedPackagedAppContext->PresentActivationTokenInfo.ActivationTokenHandle;
			TokenHandle = lpExtendedPackagedAppContext->PresentActivationTokenInfo.ActivationTokenHandle;
		}
		else if (AppExecutionAliasInfo && AppExecutionAliasInfo->BreakawayModeLaunch != TRUE)
		{
			wprintf(L"[+] AppExecutionAliasInfo is exist and no Breakaway, we try to set with AppAliasTokenHandle!\n");
			AppXTokenHandle = AppExecutionAliasInfo->TokenHandle;
			TokenHandle = AppExecutionAliasInfo->TokenHandle;
		}
		else if (ActivationToken)
		{
			AppXTokenHandle = ActivationToken;
			TokenHandle = ActivationToken;
		}

		if (NameBuffer)
		{
			RtlFreeHeap(RtlProcessHeap(), 0, NameBuffer);
			NameBuffer = NULL;
		}
		if (ExePathFullBuffer)
		{
			RtlFreeHeap(RtlProcessHeap(), 0, ExePathFullBuffer);
			ExePathFullBuffer = NULL;
		}
		RtlFreeUnicodeString(&NtImagePath);
		if (QuotedCmdLine)
		{
			RtlFreeHeap(RtlProcessHeap(), 0, QuotedCmdLine);
			QuotedCmdLine = NULL;
		}
		if (FileHandle)
		{
			NtClose(FileHandle);
			FileHandle = NULL;
		}
		if (LowBoxTokenHandle)
		{
			NtClose(LowBoxTokenHandle);
			LowBoxTokenHandle = NULL;
		}
		if (AppXEnvironment)
		{
			RtlDestroyEnvironment(AppXEnvironment);
			AppXEnvironment = NULL;
		}
		if (AppXProcessContext)
		{
			if (AppXContent)//AppXProcessContext
			{
				BasepReleaseAppXContext(AppXContent);
			}
			AppXContent = AppXProcessContext;
			AppXProcessContext = NULL;
		}
		if (SectionHandle)
		{
			NtClose(SectionHandle);
			SectionHandle = NULL;
		}
		if (ThreadHandle)
		{
			if (DebugPortHandle)
				NtRemoveProcessDebug(ProcessHandle, DebugPortHandle);
			NtTerminateProcess(ProcessHandle, STATUS_RETRY);
			NtWaitForSingleObject(ProcessHandle, FALSE, NULL);
			NtClose(ThreadHandle);
			ThreadHandle = NULL;
		}
		if (ProcessHandle)
		{
			NtClose(ProcessHandle);
			ProcessHandle = NULL;
		}
		if (IsBasepFreeAppCompatDataPresent())
		{

			BasepFreeAppCompatData(AppCompatData, AppCompatSxsData, SdbQueryResult);
			AppCompatData = NULL;
			AppCompatDataSize = 0;
			AppCompatSxsData = NULL;
			AppCompatSxsDataSize = 0;
			SdbQueryResult = NULL;
			SdbQueryResultSize = 0;
		}
		if (!VdmBinaryType && IsBasepReleaseSxsCreateProcessUtilityStructPresent())
		{
			BasepReleaseSxsCreateProcessUtilityStruct(&SxsCreateProcessUtilityStruct);
			memset(&SxsCreateProcessUtilityStruct, 0, sizeof(SxsCreateProcessUtilityStruct));
		}
		if (CaptureBuffer)
		{
			CsrFreeCaptureBuffer(CaptureBuffer);
			CaptureBuffer = NULL;
		}
		
		BasepFreeBnoIsolationParameter(&BnoIsolation);
		SearchRetry = TRUE;
		QuoteInsert = FALSE;
		QuoteCmdLine = FALSE;
		if (!lpApplicationName)
		{
			NameBuffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, MAX_PATH * sizeof(WCHAR));
			if (!NameBuffer)
			{
				BaseSetLastNTError(STATUS_NO_MEMORY);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			LastErrorValue = NULL;
			lpApplicationName = lpCommandLine;
			TempNull = (LPWSTR)lpApplicationName;
			WhiteScan = (LPWSTR)lpApplicationName;

			// check for lead quote
			if (*WhiteScan == L'\"') {
				wprintf(L"[*] Lead Quote Detected, SearchRetry Disabled...\n");
				SearchRetry = FALSE;
				WhiteScan++;
				lpApplicationName = WhiteScan;
				while (*WhiteScan) {
					if (*WhiteScan == (WCHAR)'\"') {
						TempNull = (LPWSTR)WhiteScan;
						QuoteFound = TRUE;
						break;
					}
					WhiteScan++;
					TempNull = (LPWSTR)WhiteScan;
				}
			}
			else {
			retrywsscan:
				lpApplicationName = lpCommandLine;//retry required
				while (*WhiteScan) {
					if (*WhiteScan == (WCHAR)' ' ||
						*WhiteScan == (WCHAR)'\t') {
						TempNull = (LPWSTR)WhiteScan;
						break;
					}
					WhiteScan++;
					TempNull = (LPWSTR)WhiteScan;
				}
			}
			TempChar = *TempNull;
			*TempNull = UNICODE_NULL;

			if (PathToSearch)
			{
				RtlReleasePath(PathToSearch);
				PathToSearch = NULL;
			}

			Status = RtlGetExePath(lpApplicationName, &PathToSearch);
			if (!NT_SUCCESS(Status))
			{
				wprintf(L"[-] RtlGetExePath = 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			//wprintf(L"[*] PathToSearch = %ls\n", PathToSearch);//The path to be searched for the ImageName.
			Length = SearchPathW(PathToSearch, lpApplicationName, L".exe", MAX_PATH, (LPWSTR)NameBuffer, 0);

			if (Length != 0 && Length < MAX_PATH)
			{
				DWORD FileAttributes = GetFileAttributesW(NameBuffer);//https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
				if (FileAttributes != INVALID_FILE_ATTRIBUTES)//STATUS_FILE_INVALID
				{
					if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						wprintf(L"[*] FILE_ATTRIBUTE_DIRECTORY\n");
						Status = STATUS_FILE_IS_A_DIRECTORY;
						BaseSetLastNTError(Status);
					}
					else
					{
						wprintf(L"[+] Got Valid lpApplicationName, Let's go!\n");
						*TempNull = TempChar;
						lpApplicationName = NameBuffer;
						goto CommandlineQuoteFix;
					}
				}
			}
			else if (Length >= MAX_PATH)
			{
				Status = STATUS_NAME_TOO_LONG;
				BaseSetLastNTError(Status);
			}
			//wprintf(L"[*] lpApplicationName = %ls\n", lpApplicationName);
			if (!LastErrorValue)
			{
				LastErrorValue = NtCurrentTeb()->LastErrorValue;
			}
			*TempNull = TempChar;
			if (*WhiteScan && SearchRetry)
			{
				wprintf(L"[*] lpApplicationName Invalid, Keep retrying...\n");
				WhiteScan++;
				TempNull = WhiteScan;
				QuoteInsert = TRUE;
				QuoteFound = TRUE;
				goto retrywsscan;
			}
			else
			{
				wprintf(L"[-] SearchRetry Disabled or WhiteScan is NULL, ApplicationName Search Fail\n");
				RtlSetLastWin32Error(LastErrorValue);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		else if (!(lpCommandLine) || !(*lpCommandLine))
		{
			/* We don't have a command line, so just use the application name */
			QuoteCmdLine = TRUE;
			lpCommandLine = (LPWSTR)lpApplicationName;
		}
	CommandlineQuoteFix:
		if (QuoteInsert || QuoteCmdLine)
		{
			QuotedBufferLength = wcslen(lpCommandLine) * sizeof(WCHAR) + 6;
			QuotedBuffer = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, QuotedBufferLength);
			if (QuotedBuffer) {
				StringCbCopyW(QuotedBuffer, QuotedBufferLength, L"\"");
				if (QuoteInsert) {
					TempChar = *TempNull;
					*TempNull = UNICODE_NULL;
				}
				StringCbCatW(QuotedBuffer, QuotedBufferLength, lpCommandLine);
				StringCbCatW(QuotedBuffer, QuotedBufferLength, L"\"");
				if (QuoteInsert) {
					*TempNull = TempChar;
					StringCbCatW(QuotedBuffer, QuotedBufferLength, TempNull);
				}
				lpCommandLine = QuotedBuffer;
			}
			else  //Additional 
			{
				if (QuoteInsert) {
					QuoteInsert = FALSE;
				}
				if (QuoteCmdLine) {
					QuoteCmdLine = FALSE;
				}
			}
		}
		if (!RtlDosPathNameToNtPathName_U(lpApplicationName, &NtImagePath, 0, 0))
		{
			RtlSetLastWin32Error(ERROR_PATH_NOT_FOUND);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		Status = RtlInitUnicodeStringEx(&Win32ImagePath, lpApplicationName);
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		/* Check if this was a relative path, which would explain it */
		PathType = RtlDetermineDosPathNameType_U(lpApplicationName);

		wprintf(L"[+] Final lpApplicationName = %ls\n", lpApplicationName);
		wprintf(L"[+] Final lpCommandLine = %ls\n", lpCommandLine);
		//wprintf(L"[*] Win32ImagePath: %ls\n", Win32ImagePath.Buffer);
		//wprintf(L"[*] NtImagePath: %ls\n", NtImagePath.Buffer);

		if (PathType != RtlPathTypeDriveAbsolute 
			&& PathType != RtlPathTypeLocalDevice 
			&& PathType != RtlPathTypeRootLocalDevice 
			&& PathType != RtlPathTypeUncAbsolute
			|| !BasepAdjustApplicationPath(&Win32ImagePath))
		{
			UNICODE_STRING ExePathFullBufferString = { 0 };
			ExePathFullBufferString.Buffer = NULL;
			ExePathFullBufferString.Length = 0;
			Status = RtlGetFullPathName_UstrEx(&Win32ImagePath, 0, &ExePathFullBufferString, 0, 0, 0, &PathType, 0);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			Win32ImagePath = ExePathFullBufferString;
			ExePathFullBuffer = ExePathFullBufferString.Buffer;
			ExePathFullBufferString = { 0 };
		}

		if (DesktopAppPolicy == (PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE | PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_DISABLE_PROCESS_TREE))
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}

		if (NtCurrentPeb()->IsPackagedProcess && !AppExecutionAliasInfo && !lpExtendedPackagedAppContext)
		{
			AppModelPolicyValue = AppModelPolicy_ImplicitPackageBreakaway_Denied;
			Status = AppModelPolicy_GetPolicy_Internal(
				NtCurrentThreadEffectiveToken(),//-6
				AppModelPolicy_Type_ImplicitPackageBreakaway_Internal,
				&AppModelPolicyValue,
				&PackageClaims,
				&AttributesPresent) | 0x10000000;
			wprintf(L"[*] AppModelPolicy_GetPolicy_Internal: 0x%08lx\n", Status);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			
			if (AppModelPolicyValue == AppModelPolicy_ImplicitPackageBreakaway_Allowed && PackageClaims.Flags == (PSM_ACTIVATION_TOKEN_FULL_TRUST | BREAKAWAY_INHIBITED))
				AppModelPolicyValue = AppModelPolicy_ImplicitPackageBreakaway_DeniedByApp;

			if ((AppModelPolicyValue == AppModelPolicy_ImplicitPackageBreakaway_Allowed && DESKTOP_APP_BREAKAWAY_ENABLED(DesktopAppPolicy))
				|| (AppModelPolicyValue == AppModelPolicy_ImplicitPackageBreakaway_DeniedByApp && DESKTOP_APP_BREAKAWAY_DISABLE(DesktopAppPolicy)))
			{
				//
				// wprintf(L"[!] IsCheckAppXPackageBreakawayPresent = 0x%p\n", IsCheckAppXPackageBreakawayPresent);
				// daxexec.dll!PackageInformation::VerifyFileIsInPackage
				// ->kernelbase.dll!PackageFamilyNameFromFullName
				// ->daxexec.dll!File::GetSecurityDescriptor
				// ->daxexec.dll!std::any_of_AceEnumerable::AceEnumerator__lambda_1dc4c7ce5d...............___
				// 检查AppX Package 文件对应ACE, WinBuiltinUsersSid
				//
				Status = IsCheckAppXPackageBreakawayPresent() ? CheckAppXPackageBreakaway(Win32ImagePath.Buffer, &AppXPackageBreakaway) : STATUS_UNSUCCESSFUL;
				if (!NT_SUCCESS(Status))
				{
					AppXPackageBreakaway = FALSE;
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			AppModelPolicyValue = AppModelPolicy_Type_BypassCreateProcessAppxExtension;
			AttributesPresent = 0;
			Status = AppModelPolicy_GetPolicy_Internal(
				NtCurrentThreadEffectiveToken(),
				AppModelPolicy_Type_BypassCreateProcessAppxExtension,
				&AppModelPolicyValue,
				&PackageClaims,
				&AttributesPresent);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(STATUS_UNSUCCESSFUL);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			else if (AppModelPolicyValue == AppModelPolicy_Type_BypassCreateProcessAppxExtension)
			{
				BypassAppxExtension = TRUE;
			}
		}
		if (!AppXPackageBreakaway && (PackageFullName.Length || NtCurrentPeb()->IsPackagedProcess && !BypassAppxExtension))
		{
			Status = IsBasepAppXExtensionPresent() ?
				//rcx - rdx - r8 - r9 - rest on stack
				BasepAppXExtension(
					AppXTokenHandle,
					&PackageFullName,
					SecurityCapabilities,//NULL
					lpEnvironment,//NULL
					&AppXProcessContext,
					&AppXEnvironment) : STATUS_UNSUCCESSFUL; //AppXEnvironment = NULL?
				
		wprintf(L"[*] BasepAppXExtension: 0x%08lx\n", Status);
		//wprintf(L"[*] AppXProcessContext: 0x%p\n", AppXProcessContext);
		//wprintf(L"[*] AppXProcessContext->AppXFlags: 0x%d", AppXProcessContext->AppXFlags);
			if (!NT_SUCCESS(Status))
			{
				AppXProcessContext = NULL;
				AppXEnvironment = NULL;
				BaseSetLastNTError(STATUS_UNSUCCESSFUL);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}

			if (AppXEnvironment)
				lpEnvironment = AppXEnvironment;

			if (AppXProcessContext)
			{
				//wprintf(L"[*] AppXProcessContext Stage 1\n");
				RtlInitUnicodeString(&PackageFullName, AppXProcessContext->PackageFullName);
				//wprintf(L"[*] 1 PackageFullName = %ls\n", PackageFullName.Buffer);
				//wprintf(L"[*] 1 AppXCurrentDirectory = %ls\n", AppXProcessContext->AppXCurrentDirectory);
				if (AppXProcessContext->AppXSecurityCapabilities)
				{
					wprintf(L"[+] AppXSecurityCapabilities: 0x%p\n", AppXProcessContext->AppXSecurityCapabilities);;
					SecurityCapabilities = AppXProcessContext->AppXSecurityCapabilities;
				}

				if (AppXProcessContext->AppXCurrentDirectory && !AppExecutionAliasInfo && (!lpExtendedPackagedAppContext || !lpExtendedPackagedAppContext->IsAppExecutionAliasType))
				{
					if (CurrentDirectoryHeap)
					{
						RtlFreeHeap(RtlProcessHeap(), 0, CurrentDirectoryHeap);
						CurrentDirectoryHeap = NULL;
					}
					lpCurrentDirectory = AppXProcessContext->AppXCurrentDirectory;
				}
			}
			else
			{
				PackageFullName.Buffer = NULL;
				PackageFullName.Length = 0;
				PackageFullName.MaximumLength = 0;
			}
		}
		
		Status = GetEmbeddedImageMitigationPolicy(
			&IsolationManifest,
			&MitigationOptions,
			&Win32kFilter,
			&GetMitigationPolicySuccess);//HasIsolationManifestResource 

		if (GetMitigationPolicySuccess)
		{
			wprintf(L"[+] GetMitigationPolicy Successed\n");
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			AttributeListTemp.Attributes[0].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
			AttributeListTemp.Attributes[0].Size = sizeof(PS_MITIGATION_OPTIONS_MAP);
			AttributeListTemp.Attributes[0].ReturnLength = 0;
			AttributeListTemp.Attributes[0].Value = (ULONG_PTR)&MitigationOptions;
			AttributeListTempCount = 1;
			if (Win32kFilter.FilterSet)
			{
				AttributeListTemp.Attributes[1].Attribute = PS_ATTRIBUTE_WIN32K_FILTER;
				AttributeListTemp.Attributes[1].Size = sizeof(WIN32K_SYSCALL_FILTER);
				AttributeListTemp.Attributes[1].ReturnLength = 0;
				AttributeListTemp.Attributes[1].Value = (ULONG_PTR)&Win32kFilter;
				AttributeListTempCount = 2;
			}
			BasepAddToOrUpdateAttributesList(&AttributeListTemp, AttributeListTempCount, &AttributeList, &AttributeListCount);
		}
		
		//
		// https://ti.qianxin.com/blog/articles/CVE-2023-28252-Analysis-of-In-the-Wild-Exploit-Sample-of-CLFS-Privilege-Escalation-Vulnerability/
		// https://www.coresecurity.com/core-labs/articles/understanding-cve-2022-37969-windows-clfs-lpe
		// https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation
		// https://hello.fieldeffect.com/hubfs/Blackswan/Blackswan_Technical_Write%20Up_Field_Effect.pdf
		// https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf
		// https://github.com/chromium/chromium/blob/35b9d7f718e071427444504c9dd5529cb19893e9/sandbox/win/src/process_mitigations.cc#L530
		// 
		// 由于近三年大量内核漏洞利用链涉及使用：
		// 1: NtFsControlFile 内核读取系统Token令牌地址
		// 2: NtFsControlFile 内核任意地址读写，信息泄露
		// 3: NtFsControlFile 内核堆/池风水，适用PagedPool/NonPagedPool，能做的很多
		// 4: ......
		// 尽管这相当于禁止进程进行创建和使用所有文件系统FSCTL使用权限（Pipe管道等等），
		// 但微软已决定将其漏洞利用链的FSCTL调用进行缓解控制，缓解标志可以禁止特定进程调用 NtFsControlFile。
		// 
		// Warning! Windows 11 23H2 Insider 10.0.26016.1000
		// Chromium said: [Mitigations >= Win10 22H2]
		// Note that this mitigation requires not only Win10 22H2, but also a
		// servicing update [TBD].
		// 
		// From insider SDK 10.0.25295.0 and also from MSDN.
		// TODO: crbug.com/1414570 Remove after updating SDK
		//
		// AllApplicationPackagesPolicy FsctlProcessMitigation [LPAC: Less Privileged AppContainer] 禁止LPAC的Fsctl调用 
		//
		
		if (AllApplicationPackagesPolicy & PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT)
		{
			//wprintf(L"[-] AllApplicationPackagesPolicy & PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT Status = 0x%08lx\n", Status);
			if (OSBuildNumber > 22000)
			{
				MitigationOptions.Map[2] &= ~PS_MITIGATION_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_MASK;//Cleanup Mask Already set before
				MitigationOptions.Map[2] |= PS_MITIGATION_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_ON;// Force Enable!
			}
			else
			{
				MitigationOptions.Map[2] &= ~PS_MITIGATION_OLD_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_MASK;
				MitigationOptions.Map[2] |= PS_MITIGATION_OLD_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_ON;
			}
			AttributeListTemp.Attributes[0].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
			AttributeListTemp.Attributes[0].Size = sizeof(PS_MITIGATION_OPTIONS_MAP);
			AttributeListTemp.Attributes[0].ReturnLength = 0;
			AttributeListTemp.Attributes[0].Value = (ULONG_PTR)&MitigationOptions;
			BasepAddToOrUpdateAttributesList(&AttributeListTemp, 1, &AttributeList, &AttributeListCount);
		}
		
		if (SecurityCapabilities)
		{
			Status = BasepCreateLowBox(CurrentTokenHandle, SecurityCapabilities, &LowBoxToken);

			if (!NT_SUCCESS(Status))
			{
				LowBoxToken = NULL;
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			
			Status = IsBasepAppContainerEnvironmentExtensionPresent() ? BasepAppContainerEnvironmentExtension(SecurityCapabilities->AppContainerSid, lpEnvironment, &AppXEnvironmentExtension) : STATUS_SUCCESS;

			if (!NT_SUCCESS(Status))
			{
				LowBoxToken = NULL;
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			if (LowBoxToken)
			{
				wprintf(L"[+] LowBoxToken: 0x%p\n", LowBoxToken);
				CurrentTokenHandle = LowBoxToken;
			}
			if (AppXEnvironmentExtension)
			{
				wprintf(L"[+] AppXEnvironmentExtension: 0x%p\n", AppXEnvironmentExtension);
				if (AppXEnvironment)
				{
					RtlDestroyEnvironment((PWSTR)AppXEnvironment);
				}
				AppXEnvironment = AppXEnvironmentExtension;
				lpEnvironment = AppXEnvironmentExtension;
			}
		}

		if (AppXPackageBnoIsolationDetected)
		{
			AttributeListTemp.Attributes[0].Attribute = PS_ATTRIBUTE_BNO_ISOLATION;
			AttributeListTemp.Attributes[0].Size = sizeof(PS_BNO_ISOLATION_PARAMETERS);
			AttributeListTemp.Attributes[0].ReturnLength = 0;
			AttributeListTemp.Attributes[0].Value = (ULONG_PTR)&MitigationOptions;
			BasepAddToOrUpdateAttributesList(&AttributeListTemp, 1, &AttributeList, &AttributeListCount);
			IsolationEnabled = TRUE;
		}

		if (!IsolationEnabled)
		{
			CurrentTokenHandle = AppXTokenHandle;// Assumed
		}
		else if (SecurityCapabilities || NtCurrentPeb()->IsAppContainer)
		{
			//
			// 检查已从前方移动到这.
			// Isolation限制，禁止AppContainer, AppContainer isn't supported yet
			//
			BaseSetLastNTError(STATUS_NOT_SUPPORTED);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		else
		{
			// Win 11  
			// Status = BasepProcessBnoIsolationParameter(CurrentTokenHandle, &BnoIsolation)
			// if...
			wprintf(L"[!] BnoIsolation Enabled: %ls\n", BnoIsolation.IsolationPrefix.Buffer);
			CurrentTokenHandle = TokenHandle;
			if (BnoIsolation.Handles)
			{
				Status = STATUS_INVALID_PARAMETER;
			}
			else 
			{
				if (!BnoIsolation.IsolationEnabled)
				{
					Status = STATUS_SUCCESS;
				}
				else if (!BnoIsolation.IsolationPrefix.Buffer)
				{
					Status = STATUS_INVALID_PARAMETER;
				}
				else // BnoIsolation.IsolationEnabled && BnoIsolation.IsolationPrefix.Buffer
				{
					Status = BasepCreateBnoIsolationObjectDirectories(CurrentTokenHandle, &BnoIsolation);
				}
			}
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}

		if (lpCurrentDirectory)
		{
			DWORD FileAttributes = GetFileAttributesW(lpCurrentDirectory);
			if (FileAttributes == INVALID_FILE_ATTRIBUTES || (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
			{
				//STATUS_NOT_A_DIRECTORY;
				RtlSetLastWin32Error(ERROR_DIRECTORY);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		if (CurrentTokenHandle)
		{
			wprintf(L"[*] CurrentTokenHandle: 0x%p\n", CurrentTokenHandle);
			AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_TOKEN;
			AttributeList.Attributes[AttributeListCount].Size = sizeof(HANDLE);
			AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
			AttributeList.Attributes[AttributeListCount].ValuePtr = CurrentTokenHandle;
			AttributeListCount++;
		}

		if (AppXProcessContext && AppXProcessContext->u1.s1.AppXProtectedProcessLight)
		{
			// win 11 kernel32.dll!BasepCheckPplSupport->kernelbase.dll!AppXCheckPplSupport->WinTrust.dll!WinVerifyTrust
			wprintf(L"[*] AppXProtectedProcessLight\n");
			AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_PROTECTION_LEVEL;// PsAttributeProtectionLevel
			AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_PROTECTION);
			AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
			AttributeList.Attributes[AttributeListCount].Value = PsProtectedValue(PsProtectedSignerApp, FALSE, PsProtectedTypeProtectedLight);//ULONG_PTR
			AttributeListCount++;
			ProcessFlags |= PROCESS_CREATE_FLAGS_PROTECTED_PROCESS;
		}

		if (bInheritHandles)
			ProcessFlags |= PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
		else
			ProcessFlags &= ~PROCESS_CREATE_FLAGS_INHERIT_HANDLES;

		memset(&CreateInfo, 0, sizeof(PS_CREATE_INFO));
		CreateInfo.Size = sizeof(PS_CREATE_INFO);
		if (!VdmBinaryType && !DefaultInheritOnly)
		{
			if ((StartupInfo.dwFlags & STARTF_USESTDHANDLES) == 0 && !ParentProcessHandle && (dwCreationFlags & (CREATE_NO_WINDOW | CREATE_NEW_CONSOLE | DETACHED_PROCESS)) == 0)// none of CREATE_NO_WINDOW CREATE_NEW_CONSOLE DETACHED_PROCESS
			{
				wprintf(L"[*] StdHandle Mode 1\n");
				StdHandle.StdHandleSubsystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
				StdHandle.StdHandleState = PsRequestDuplicate;
				StdHandle.PseudoHandleMask = 0;
				AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
				AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_STD_HANDLE_INFO);
				AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
				AttributeList.Attributes[AttributeListCount].ValuePtr = &StdHandle;
				AttributeListCount++;
			}
			if ((StartupInfo.dwFlags & STARTF_USESTDHANDLES) && ParentProcessHandle)
			{
				wprintf(L"[*] StdHandle Mode 2\n");
				StdHandle.StdHandleSubsystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
				StdHandle.StdHandleState = PsAlwaysDuplicate;
				StdHandle.PseudoHandleMask = 0;
				AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
				AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_STD_HANDLE_INFO);
				AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
				AttributeList.Attributes[AttributeListCount].ValuePtr = &StdHandle;
				AttributeListCount++;
			}
		}
		if (!(dwCreationFlags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) || NtCurrentPeb()->ReadImageFileExecOptions)
		{
			if (AlreadyQueryImageFileDebugger == TRUE)
			{
				AlreadyQueryImageFileDebugger = FALSE;
				CreateInfo.InitState.u1.s1.IFEOSkipDebugger = TRUE;			//0x04
			}
		}
		else
		{	
			CreateInfo.InitState.u1.s1.IFEOSkipDebugger = TRUE;				//0x04
			CreateInfo.InitState.u1.s1.IFEODoNotPropagateKeyState = TRUE;	//0x08 -> 0x0c
		}
		CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
		CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = IMAGE_FILE_DLL;
		CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

		if (!StartupInfo.lpDesktop)
			StartupInfo.lpDesktop = NtCurrentPeb()->ProcessParameters->DesktopInfo.Buffer;

		if (!AppXProcessContext || !AppXProcessContext->PackageFullName || !(*AppXProcessContext->PackageFullName) || AppXProcessContext->u1.s1.AppXManifestDetected) //AppXManifestDetect
		{
			//wprintf(L"[*] Enable DetectManifest\n");
			CreateInfo.InitState.u1.s1.DetectManifest = TRUE;//if ***, will not use DetectManifest 
		}
		RtlWow64GetProcessMachines(NtCurrentProcess(), &CurrentProcessMachine, &TargetProcessMachine);
		/*
		if (TargetProcessMachine == IMAGE_FILE_MACHINE_ARM64 && IsBasepQueryModuleChpeSettingsPresent())
		{
			BasepQueryModuleChpeSettings(// Compiled Hybrid Portable Executable
				&ChpeModSettingsOut,
				32,
				Win32PathName.Buffer,
				&ModuleName, //PUNICODE_STRING
				lpEnvironment,
				&PackageFullName,
				&SdbQueryResult,
				&SdbQueryResultSize,
				&AppCompatSxsData,
				&AppCompatSxsDataSize
				&dwLuaRunlevelFlags))

		}
		{
			 if ( (dwLuaRunlevelFlags & 0x800000000) != 0 ) NoCfgCheck
			 ......................
			{
				MitigationOptions[0] = MitigationOptions[0] & [XFG Disable];// XFG Disable
				AttributeListTemp.Attributes[0].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
				AttributeListTemp.Attributes[0].Size = sizeof(PS_MITIGATION_OPTIONS_MAP);
				AttributeListTemp.Attributes[0].ReturnLength = 0;
				AttributeListTemp.Attributes[0].Value = (ULONG_PTR)MitigationOptions;
				v277 = 1;
				LODWORD(v182) = 27;
				BasepAddToOrUpdateAttributesList(&AttributeListTemp, AttributeListTempCount, &AttributeList, &AttributeListCount);
			}
			......
		}*/

		//DEBUG
		if (AppXProcessContext)
		{
			wprintf(L"[*] AppXProcessContext->AppXDllDirectory: %ls\n", AppXProcessContext->AppXDllDirectory);
			wprintf(L"[*] AppXProcessContext->AppXRedirectionDllName: %ls\n", AppXProcessContext->AppXRedirectionDllName);
		}

		ProcessParameters = BasepCreateProcessParameters(
			lpApplicationName,
			&Win32ImagePath,
			lpCurrentDirectory,
			lpCommandLine,
			AppXProcessContext ? AppXProcessContext->AppXDllDirectory : NULL,
			AppXProcessContext ? AppXProcessContext->AppXRedirectionDllName : NULL,
			PackageFullName.Length != 0,
			lpEnvironment,
			&StartupInfo,
			dwCreationFlags,
			DefaultInheritOnly,//11 False DefaultInheritOnly 的作用是继承当前进程的std标准输入输出流->重定向
			ProcessFlags | (AppXPackageBreakaway ? PROCESS_CREATE_FLAGS_PACKAGE_BREAKAWAY : 0),
			&ConsoleHandleInfo, 
			ParentProcessHandle);//14

		//ProcessParameters->ConsoleHandle = 0;
		/*
		wprintf(L"[*] MaximumLength: 0x%08lx --- Length: 0x%08lx\n", ProcessParameters->MaximumLength, ProcessParameters->Length);
		wprintf(L"[*] Flags: 0x%08x\n", ProcessParameters->Flags);
		wprintf(L"[*] ShowWindowFlags: %d\n", ProcessParameters->ShowWindowFlags);
		wprintf(L"[*] WindowFlags: %d\n", ProcessParameters->WindowFlags);
		wprintf(L"[*] ConsoleHandle: 0x%08x --- ConsoleFlags: 0x%08x\n", ProcessParameters->ConsoleHandle, ProcessParameters->ConsoleFlags);
		wprintf(L"[*] ConsoleFlags: %d\n", ProcessParameters->ConsoleFlags);
		wprintf(L"[*] EnvironmentVersion: %lld -- EnvironmentSize  = %lld\n", ProcessParameters->EnvironmentVersion,ProcessParameters->EnvironmentSize);
		wprintf(L"[*] CurrentDirectory: %ls --- Length = %d\n", ProcessParameters->CurrentDirectory.DosPath.Buffer, ProcessParameters->CurrentDirectory.DosPath.Length);

		wprintf(L"[*] CURDIR->CurrentDirectory: %ls\n", ProcessParameters->CurrentDirectory.DosPath.Buffer);
		wprintf(L"[*] DllPath: %ls -- Length: %d\n", ProcessParameters->DllPath.Buffer, ProcessParameters->DllPath.Length);

		wprintf(L"[*] ImagePathName: %ls --- ImagePathName.MaximumLength = %d, ImagePathName.Length = %d\n", ProcessParameters->ImagePathName.Buffer, ProcessParameters->ImagePathName.MaximumLength, ProcessParameters->ImagePathName.Length);
		wprintf(L"[*] CommandLine: %ls, CommandLine.MaximumLength = %d, CommandLine.Length = %d\n", ProcessParameters->CommandLine.Buffer, ProcessParameters->CommandLine.MaximumLength, ProcessParameters->CommandLine.Length);
		wprintf(L"[*] WindowTitle: %ls --- WindowTitle.MaximumLength = %d, WindowTitle.Length = %d\n", ProcessParameters->WindowTitle.Buffer, ProcessParameters->WindowTitle.MaximumLength, ProcessParameters->WindowTitle.Length);
		wprintf(L"[*] ProcessGroupId: %d\n", ProcessParameters->ProcessGroupId);
		*/

		if (!ProcessParameters)
		{
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (AppXProcessContext && AppXProcessContext->u1.s1.AppXGlobalizationOverride)
		{
			ProcessParameters->Flags |= RTL_USER_PROC_APPX_GLOBAL_OVERRIDE;
		}
		if ((AppExecutionAliasInfo || (lpExtendedPackagedAppContext && lpExtendedPackagedAppContext->IsAppExecutionAliasType == TRUE)) && !lpCurrentDirectory)
		{
			DosPathLength = ProcessParameters->CurrentDirectory.DosPath.Length;
			PWSTR TempHeap = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, (SIZE_T)DosPathLength + sizeof(UNICODE_NULL));
			CurrentDirectoryHeap = TempHeap;
			if (!TempHeap)
			{
				BaseSetLastNTError(STATUS_NO_MEMORY);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			StringCbCopyW(TempHeap, DosPathLength + sizeof(UNICODE_NULL), ProcessParameters->CurrentDirectory.DosPath.Buffer);
			lpCurrentDirectory = TempHeap;
		}

		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_CHPE;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(BOOLEAN);
		AttributeList.Attributes[AttributeListCount].ReturnLength = NULL;
		//AttributeList.Attributes[AttributeListCount].ValuePtr = QueryChpeConfiguration(&NtImageName, (ChpeModSetting.Reserved3 >> 6) & 1);
		ChpeOption = TRUE;
		AttributeList.Attributes[AttributeListCount].Value = ChpeOption;
		AttributeListCount++;

		AttributeList.Attributes[0].Size = NtImagePath.Length;
		AttributeList.Attributes[0].ValuePtr = NtImagePath.Buffer;
		AttributeList.TotalLength = AttributeListCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);

		// win 11 ExtendedPackagedAppContext and......
		if (lpExtendedPackagedAppContext && lpExtendedPackagedAppContext->Breakaway != TRUE)
		{
			if (NtCurrentTeb()->IsImpersonating)
			{
				Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &SaveImpersonateTokenHandle);
				if (Status < 0)
				{
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			AppXPackageImpersonateToken = lpExtendedPackagedAppContext->PresentActivationTokenInfo.ActivationTokenHandle;
		}
		else if (AppExecutionAliasInfo && AppExecutionAliasInfo->BreakawayModeLaunch != TRUE)
		{
			wprintf(L"[*] AppExecutionAlias Impersonating!\n");
			if (NtCurrentTeb()->IsImpersonating)
			{
				Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &SaveImpersonateTokenHandle);
				if (Status < 0)
				{
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			AppXPackageImpersonateToken = AppExecutionAliasInfo->TokenHandle;
		}
		if (AppXPackageImpersonateToken)
		{
			if (!ImpersonateLoggedOnUser(AppXPackageImpersonateToken))
			{
				if (SaveImpersonateTokenHandle)
					NtClose(SaveImpersonateTokenHandle);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			ThreadTokenImpersonated = TRUE;
			CurrentTokenHandle = TokenHandle;
		}
		

		//wprintf(L"[*] dwCreationFlags: 0x%08x\n", dwCreationFlags);
		//wprintf(L"[*] InitFlags 0x%08lx, AdditionalFileAccess: 0x%08lx\n", CreateInfo.InitState.u1.InitFlags, CreateInfo.InitState.AdditionalFileAccess);
		wprintf(L"[*] ProcessFlags: 0x%08lx\n", ProcessFlags);
		wprintf(L"[*] AttributeListCount: %ld, TotalLength: %lld\n", AttributeListCount, AttributeList.TotalLength);

		Status = NtCreateUserProcess(&ProcessHandle, &ThreadHandle, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, &AttributeList);
		if (ThreadTokenImpersonated == TRUE)
		{
			ThreadTokenImpersonated = FALSE;
			if (SaveImpersonateTokenHandle)
			{
				ImpersonateRebackSuccess = ImpersonateLoggedOnUser(SaveImpersonateTokenHandle);
				NtClose(SaveImpersonateTokenHandle);
				if (!ImpersonateRebackSuccess)
				{
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			else
			{
				RevertToSelf();
			}
		}

		RtlDestroyProcessParameters(ProcessParameters);
		wprintf(L"==================================================================\n");
		if (NT_SUCCESS(Status))
		{
			CreateInfoOutPut(CreateInfo);
			SectionImageInfomationOutPut(SectionImageInfomation);

			wprintf(L"[+] NtCreateUserProcess Success! PID=%lld, TID=%lld\n", (ULONGLONG)ClientId.UniqueProcess, (ULONGLONG)ClientId.UniqueThread);
			//wprintf(L"[+] OutputFlags: 0x%08x\n", CreateInfo.SuccessState.u2.OutputFlags);//0x08 // 0x0a = 0x08 | 0x02
			break;
		}
		ProcessHandle = NULL;
		ThreadHandle = NULL;
		wprintf(L"[-] NtCreateUserProcess Fail: 0x%08lx, CreateInfo.State = %d\n", Status, CreateInfo.State);
		//wprintf(L"[-] OutputFlags: 0x%08x\n", CreateInfo.SuccessState.u2.OutputFlags);

		switch (CreateInfo.State)
		{

		case PsCreateInitialState:
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
			break;

		case PsCreateFailOnFileOpen:
			if (OSBuildNumber >= 21332 && !AlreadyGetPackagedAppInfo && IsBasepGetPackagedAppInfoForFilePresent())
			{
				NTSTATUS PackagedAppStatus = BasepGetPackagedAppInfoForFile(lpApplicationName, CurrentTokenHandle, TRUE, &lpExtendedPackagedAppContext);
				AlreadyGetPackagedAppInfo = TRUE;
				if (NT_SUCCESS(PackagedAppStatus) && lpExtendedPackagedAppContext)
				{
					wprintf(L"[%d] %ls: BasepGetPackagedAppInfoForFile Fail: %ls\n", CreateInfo.State, L"PsCreateFailOnFileOpen", lpExtendedPackagedAppContext->ApplicationUserModelId);
					lpApplicationName = lpExtendedPackagedAppContext->PackageImagePath;
					if (lpExtendedPackagedAppContext->Breakaway == TRUE)
					{
						if (lpExtendedPackagedAppContext->IsAppExecutionAliasType)
						{
							PackageCommandLineLength = (sizeof(WCHAR) * (wcslen(lpCommandLine) + wcslen(lpExtendedPackagedAppContext->ApplicationUserModelId)) + sizeof(UNICODE_NULL)+ 2);
							PackageNewCommandLine = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, PackageCommandLineLength);
							if (!PackageNewCommandLine)//???
								break;
							StringCbCopyW(PackageNewCommandLine, PackageCommandLineLength, lpExtendedPackagedAppContext->ApplicationUserModelId);
							PackageCommandLineLink = L" ";
						}
						else
						{
							PackageCommandLineLength = (sizeof(WCHAR) * (wcslen(lpCommandLine) + wcslen(lpExtendedPackagedAppContext->ApplicationUserModelId) + wcslen(L" PackagedDataInfo: ")) + 2);
							PackageNewCommandLine = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, PackageCommandLineLength);
							if (!PackageNewCommandLine)//???
								break;
							StringCbCopyW(PackageNewCommandLine, PackageCommandLineLength, lpExtendedPackagedAppContext->ApplicationUserModelId);
							PackageCommandLineLink = L" PackagedDataInfo: ";
						}
						StringCbCatW(PackageNewCommandLine, PackageCommandLineLength, PackageCommandLineLink);
						StringCbCatW(PackageNewCommandLine, PackageCommandLineLength, lpCommandLine);
					}
					else
					{
						AppXPackageBreakaway = FALSE;
						CurrentTokenHandle = lpExtendedPackagedAppContext->ActivationTokenInfo.ActivationTokenHandle;
						RtlInitUnicodeString(&PackageFullName, lpExtendedPackagedAppContext->PackageFullName);

						PackageCommandLineLength = sizeof(WCHAR) * wcslen(lpCommandLine) + 2;
						PackageNewCommandLine = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, PackageCommandLineLength);
						if (!PackageNewCommandLine)//???
							break;
						StringCbCopyExW(PackageNewCommandLine, PackageCommandLineLength, lpCommandLine, NULL, NULL, STRSAFE_IGNORE_NULLS | STRSAFE_NULL_ON_FAILURE);
					}
					lpCommandLine = PackageNewCommandLine;
					break;
				}
				
				wprintf(L"[%d] %ls: BasepGetPackagedAppInfoForFile Fail: 0x%08lx\n", CreateInfo.State, L"PsCreateFailOnFileOpen", PackagedAppStatus);
			}

			if (!AppExecutionAliasInfo && (Status == STATUS_IO_REPARSE_TAG_NOT_HANDLED || Status == STATUS_ACCESS_DENIED))
			{
				AliasStatus = STATUS_NOT_IMPLEMENTED;// TEST
				if (Status == STATUS_ACCESS_DENIED)
				{
					
					AliasStatus = LoadAppExecutionAliasInfoForExecutable(
						NULL,
						Win32ImagePath.Buffer,
						AppAliasTokenHandle,
						RtlProcessHeap(),
						&AppExecutionAliasInfo);
					
					//wprintf(L"[*] ValidateAppXAliasFallback Address: 0x%p\n", ValidateAppXAliasFallback);
					if (NT_SUCCESS(AliasStatus) && AppExecutionAliasInfo)
					{
						AliasStatus = ValidateAppXAliasFallback(Win32ImagePath.Buffer, AppExecutionAliasInfo);
					}

				}
				else if (IsLoadAppExecutionAliasInfoExPresent())
				{

					//
					// STATUS_IO_REPARSE_TAG_NOT_HANDLED -> AppX
					//
					AliasStatus = LoadAppExecutionAliasInfoEx(Win32ImagePath.Buffer, TokenHandle, &AppExecutionAliasInfo);//Alias Core 关键核心
					wprintf(L"[%d] %ls: LoadAppExecutionAliasInfoEx: 0x%08lx\n", CreateInfo.State, L"PsCreateFailOnFileOpen", AliasStatus);
				}
				else
				{
					AliasStatus = STATUS_NOT_IMPLEMENTED;
				}

				if (NT_SUCCESS(AliasStatus) && AppExecutionAliasInfo)
				{
					lpApplicationName = AppExecutionAliasInfo->AppAliasBaseImagePath;
					TokenHandle = AppExecutionAliasInfo->TokenHandle;

					// Win 11 BuildAppExecutionAliasCommandLine
					if (AppExecutionAliasInfo->BreakawayModeLaunch == TRUE)
					{
						wprintf(L"[%d] %ls: AppXAliasCommandline Breakaway 1\n", CreateInfo.State, L"PsCreateFailOnFileOpen"); //SystemUWPLauncher.exe
						SIZE_T AppXAliasCommandlineLength = sizeof(WCHAR) * (wcslen(AppExecutionAliasInfo->PackageFamilyName) + wcslen(lpCommandLine) + 2);
						AppXAliasCommandline = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), 0, AppXAliasCommandlineLength);
						if (AppXAliasCommandline)
						{
							StringCbCopyW(AppXAliasCommandline, AppXAliasCommandlineLength, AppExecutionAliasInfo->PackageFamilyName);
							StringCbCatW(AppXAliasCommandline, AppXAliasCommandlineLength, L" ");
							StringCbCatW(AppXAliasCommandline, AppXAliasCommandlineLength, lpCommandLine);
						}
					}
					else
					{
						wprintf(L"[%d] %ls: AppXAliasCommandline Normal 2\n", CreateInfo.State, L"PsCreateFailOnFileOpen");
						RtlInitUnicodeString(&PackageFullName, AppExecutionAliasInfo->AppXPackageName);//Win 11 Keep
						AppXPackageBreakaway = FALSE;
						SIZE_T AppXAliasCommandlineLength = sizeof(WCHAR) * wcslen(lpCommandLine) + 2;
						AppXAliasCommandline = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, AppXAliasCommandlineLength);
						if (AppXAliasCommandline)
						{
							StringCbCopyExW(AppXAliasCommandline, AppXAliasCommandlineLength, lpCommandLine, 0, 0, 0);

						}
						wprintf(L"[%d] %ls: PackageFullName: %ls\n", CreateInfo.State, L"PsCreateFailOnFileOpen", PackageFullName.Buffer);
					}
					if(AppXAliasCommandline)
						lpCommandLine = AppXAliasCommandline;

					//
					// New: AppExecutionAliasInfo BnoIsolation Name 10.0.26020.1000
					//
					if (OSBuildNumber >= 25357 && AppExecutionAliasInfo->AliasPackagesIsolationPrefix)
					{
						BasepFreeBnoIsolationParameter(&BnoIsolation);
						RtlInitUnicodeString(&BnoIsolation.IsolationPrefix, AppExecutionAliasInfo->AliasPackagesIsolationPrefix);
						BnoIsolation.IsolationEnabled = TRUE;
						AppXPackageBnoIsolationDetected = TRUE;
					}

					break;// OK
				}
				else if (AliasStatus == (ERROR_PACKAGE_UPDATING | 0xC0070000))
				{
					Status = ERROR_PACKAGE_UPDATING | 0xC0070000;
				}
			}
		
			if (RtlIsDosDeviceName_U(lpApplicationName))
			{
				RtlSetLastWin32Error(ERROR_BAD_DEVICE);
			}
			else
			{
				BaseSetLastNTError(Status);
			}
			bStatus = FALSE;
			goto Leave_Cleanup;

		case PsCreateFailOnSectionCreate:
			FileHandle = CreateInfo.FailSection.FileHandle;

			if (Status == STATUS_ACCESS_DENIED)
			{
				RtlSetLastWin32Error(ERROR_ACCESS_DENIED);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			if (IsImageValidFixed)
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			if (Status == STATUS_INVALID_IMAGE_NOT_MZ && NtImagePath.Length >= 8)
			{
				// must be a .bat or .cmd file
				PWSTR Last4 = &NtImagePath.Buffer[NtImagePath.Length / sizeof(WCHAR) - 4];

				DWORD EnvLength = 0;
				if (!_wcsnicmp(Last4, L".bat", 4) || !_wcsnicmp(Last4, L".cmd", 4))
				{
					IsBatchFile = TRUE;
					NewCommandLine = (LPWSTR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, *KernelBaseGetGlobalData(), static_cast<SIZE_T>(2 * MAX_PATH) + 6);
					if (!NewCommandLine)
					{
						BaseSetLastNTError(STATUS_NO_MEMORY);
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
					EnvLength = GetEnvironmentVariableW(L"ComSpec", NewCommandLine, MAX_PATH);
					if (EnvLength >= MAX_PATH)
					{
						BaseSetLastNTError(STATUS_NO_SUCH_FILE);
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
					if (!EnvLength)
					{
						
						if (GetEnvironmentVariableW(L"SystemRoot", NewCommandLine, MAX_PATH - DefaultComSpecPathStringCount) > MAX_PATH - DefaultComSpecPathStringCount - 1) // wcslen("\\system32\\cmd.exe")
						{
							BaseSetLastNTError(STATUS_NOT_A_DIRECTORY);
							bStatus = FALSE;
							goto Leave_Cleanup;
						}
						StringCbCatW(NewCommandLine, MAX_PATH, DefaultComSpecPath);// RtlStringCchCatW ?= StringCbCatW
					}
					StringCbCatW(NewCommandLine, MAX_PATH + 3, L" /c");// RtlStringCchCatW ?= StringCbCatW

					if (!BuildSubSysCommandLine(SearchRetry, NewCommandLine, NULL, lpCommandLine, &SubSysCommandLine))
					{
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
					lpCommandLine = SubSysCommandLine.Buffer;
					lpApplicationName = NULL;
					IsImageValidFixed = TRUE;
					break;
				}
			}

			if ((dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL) == 0)
			{
				bSaferChecksNeeded = TRUE;
				switch (Status) {
				case STATUS_INVALID_IMAGE_NE_FORMAT:
				case STATUS_INVALID_IMAGE_WIN_16:
				case STATUS_FILE_IS_OFFLINE:
				case STATUS_INVALID_IMAGE_PROTECT:
					break;
				case STATUS_INVALID_IMAGE_NOT_MZ:
					if (IsBaseIsDosApplicationPresent() && BaseIsDosApplication(&NtImagePath))
					{
						break;
					}

				default:
					bSaferChecksNeeded = FALSE;
				}
				if (bSaferChecksNeeded)
				{
					wprintf(L"[!] Winsafer Restrictions Check. Should be done for non .NET images only.\n");
					wprintf(L"[!] If this is the first time then we will have to do Safer checks.\n");
					wprintf(L"[!] Note that we do not impose any restrictions on the interpreter itself since it is part of OS.\n");
					SaferStatus = IsBasepCheckWinSaferRestrictionsPresent() ?
						BasepCheckWinSaferRestrictions(
							CurrentTokenHandle,
							lpApplicationName,
							FileHandle,
							&PackageFullName) : STATUS_SUCCESS;
					if (!NT_SUCCESS(SaferStatus))
					{
						BaseSetLastNTError(SaferStatus);
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
				}
			}//dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL

			if (Status == STATUS_INVALID_IMAGE_WIN_16)
			{
				init2();
				if (IsNtVdm64CreateProcessInternalWPresent())
				{
					bStatus = NtVdm64CreateProcessInternalW(
						CurrentTokenHandle,
						lpApplicationName,
						lpCommandLine,
						lpProcessAttributes,
						lpThreadAttributes,
						bInheritHandles,
						dwCreationFlags,
						lpEnvironment,
						lpCurrentDirectory,
						lpStartupInfo,
						lpProcessInformation,
						NULL);
					wprintf(L"[*] NtVdm64CreateProcessInternalW bStatus = %d\n", bStatus);
				}
				else
					bStatus = FALSE;
				if (!bStatus && NtCurrentTeb()->LastErrorValue == ERROR_EXE_MACHINE_TYPE_MISMATCH && IsRaiseInvalid16BitExeErrorPresent())
				{
					RaiseInvalid16BitExeError(&NtImagePath);
				}
				goto Leave_Cleanup;
			}
			else
			{
				if (IsBasepProcessInvalidImagePresent())
					bStatus = BasepProcessInvalidImage(
						Status,
						CurrentTokenHandle,
						Win32ImagePath.Buffer,
						&lpApplicationName,
						&lpCommandLine,
						lpCurrentDirectory,
						&dwCreationFlags,
						&bInheritHandles,
						&NtImagePath,
						&IsWowBinary,
						&lpEnvironment,
						&StartupInfo,
						&ApiMessage, 
						&VdmTaskId,
						&SubSysCommandLine,
						&AnsiStringVDMEnv,
						&UnicodeStringVDMEnv,
						&VdmCreationState,
						&VdmBinaryType,
						&VdmPartiallyCreated,
						&VdmWaitHandle);
				else
					bStatus = FALSE;
				if (!bStatus)
					goto Leave_Cleanup;
				if (VdmWaitHandle)
					goto FinalSuccess;
			}
			IsImageValidFixed = TRUE;
			break;

		case PsCreateFailExeFormat:
			RtlSetLastWin32Error(ERROR_BAD_EXE_FORMAT);
			bStatus = FALSE;
			goto Leave_Cleanup;
			break;

		case PsCreateFailMachineMismatch:
			if (TargetProcessMachine != IMAGE_FILE_MACHINE_ARM64)
			{
				ULONG_PTR ErrorParameters = NULL;
				ULONG ErrorResponse = 0;
				ErrorResponse = ResponseOk;
				ErrorParameters = (ULONG_PTR)&NtImagePath;
				NtRaiseHardError(STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE, 1, 1, (PULONG_PTR)&ErrorParameters, OptionOk, &ErrorResponse);
			}
			if (NtCurrentPeb()->ImageSubsystemMajorVersion <= IMAGE_SUBSYSTEM_WINDOWS_CUI) {
				Win32Error = ERROR_BAD_EXE_FORMAT;
			}
			else
			{
				Win32Error = ERROR_EXE_MACHINE_TYPE_MISMATCH;
			}
			RtlSetLastWin32Error(Win32Error);
			bStatus = FALSE;
			goto Leave_Cleanup;
			break;

		case PsCreateFailExeName:
			IFEOKey = CreateInfo.ExeName.IFEOKey;
			if (!ImageFileDebuggerCommand)
			{
				ImageFileDebuggerCommand = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH + sizeof(UNICODE_NULL));
				if (!ImageFileDebuggerCommand)
				{
					NtClose(IFEOKey);
					RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}

			Status = LdrQueryImageFileKeyOption(IFEOKey, L"Debugger", REG_SZ, ImageFileDebuggerCommand, sizeof(WCHAR) * MAX_PATH, &ReturnedLength);
			if (OSBuildNumber < 21313) //22000 ?
				NtClose(IFEOKey); //Win 11 Post? or Win 10 Preview?
			if (AppXProcessContext)
				ReturnedLength = 0;
			if (NT_SUCCESS(Status) && ReturnedLength >= 2 && *ImageFileDebuggerCommand)
			{
		
				ImageFileDebuggerCommand[MAX_PATH] = NULL;
				if (!BuildSubSysCommandLine(3, ImageFileDebuggerCommand, 0, lpCommandLine, &SubSysCommandLine))
				{
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
				lpCommandLine = SubSysCommandLine.Buffer;
				lpApplicationName = NULL;
				break;
			}
			else
			{
				RtlFreeHeap(RtlProcessHeap(), 0, (PVOID)ImageFileDebuggerCommand);
				ImageFileDebuggerCommand = NULL;
			}
			if (!AppExecutionAliasInfo && OSBuildNumber >= 21313)
			{
				//
				// https://docs.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-extensions
				//
				wprintf(L"[%d] %ls: Try to Redirect Package Executable via OSBuildNumber >= 21313\n", CreateInfo.State, L"PsCreateFailExeName");
				Status = LoadAppExecutionAliasInfoForExecutable(IFEOKey, Win32ImagePath.Buffer, CurrentTokenHandle, RtlProcessHeap(), &AppExecutionAliasInfo);

				if (NT_SUCCESS(Status) && AppExecutionAliasInfo)
				{
					lpApplicationName = AppExecutionAliasInfo->AppAliasBaseImagePath;
					TokenHandle = AppExecutionAliasInfo->TokenHandle;

					//
					// BuildAppExecutionAliasCommandLine and...
					//
					if (AppExecutionAliasInfo->BreakawayModeLaunch == TRUE)
					{
						wprintf(L"[%d] %ls: AppXAliasCommandline Breakaway 1\n", CreateInfo.State, L"PsCreateFailExeName"); //SystemUWPLauncher.exe
						SIZE_T AppXAliasCommandlineLength = sizeof(WCHAR) * (wcslen(AppExecutionAliasInfo->PackageFamilyName) + wcslen(lpCommandLine) + 2);
						AppXAliasCommandline = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), 0, AppXAliasCommandlineLength);
						if (AppXAliasCommandline)
						{
							StringCbCopyW(AppXAliasCommandline, AppXAliasCommandlineLength, AppExecutionAliasInfo->PackageFamilyName);
							StringCbCatW(AppXAliasCommandline, AppXAliasCommandlineLength, L" ");
							StringCbCatW(AppXAliasCommandline, AppXAliasCommandlineLength, lpCommandLine);
						}
					}
					else
					{
						wprintf(L"[%d] %ls: AppXAliasCommandline Normal 2\n", CreateInfo.State, L"PsCreateFailExeName");
						RtlInitUnicodeString(&PackageFullName, AppExecutionAliasInfo->AppXPackageName);//Win 11 Keep
						AppXPackageBreakaway = FALSE;
						SIZE_T AppXAliasCommandlineLength = sizeof(WCHAR) * wcslen(lpCommandLine) + 2;
						AppXAliasCommandline = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, AppXAliasCommandlineLength);
						if (AppXAliasCommandline)
						{
							StringCbCopyExW(AppXAliasCommandline, AppXAliasCommandlineLength, lpCommandLine, 0, 0, 0);
						}
						wprintf(L"[%d] %ls: PackageFullName: %ls\n", CreateInfo.State, L"PsCreateFailExeName", PackageFullName.Buffer);
					}
					if (AppXAliasCommandline)
						lpCommandLine = AppXAliasCommandline;

					//
					// New: AppExecutionAliasInfo BnoIsolation Name
					//
					if (OSBuildNumber >= 25357 && AppExecutionAliasInfo->AliasPackagesIsolationPrefix)
					{
						BasepFreeBnoIsolationParameter(&BnoIsolation);
						RtlInitUnicodeString(&BnoIsolation.IsolationPrefix, AppExecutionAliasInfo->AliasPackagesIsolationPrefix);
						BnoIsolation.IsolationEnabled = TRUE;
						AppXPackageBnoIsolationDetected = TRUE;
					}
				}
				else if (Status == (ERROR_PACKAGE_UPDATING | 0xC0070000))
				{
					NtClose(IFEOKey);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			if (OSBuildNumber >= 21313)
				NtClose(IFEOKey);
			AlreadyQueryImageFileDebugger = TRUE;
			break;

		default:
			break;
	}
	RetryNtCreateUserProcess:
		wprintf(L"[!] Retry NtCreateUserProcess !!!\n");
		wprintf(L"================================================================================\n");
	}
	SectionHandle = CreateInfo.SuccessState.SectionHandle;
	FileHandle = CreateInfo.SuccessState.FileHandle;
	if (SectionImageInfomation.SubSystemType != IMAGE_SUBSYSTEM_WINDOWS_GUI &&
		SectionImageInfomation.SubSystemType != IMAGE_SUBSYSTEM_WINDOWS_CUI)
	{
		RtlSetLastWin32Error(ERROR_CHILD_NOT_COMPLETE);
		wprintf(L"[-] ERROR_CHILD_NOT_COMPLETE = %ld. The application cannot be run in Win32 mode.\n", ERROR_CHILD_NOT_COMPLETE);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}

	// 
	// Make sure image is at least 3.10.
	// And not greater than what we are.
	//

	if (SectionImageInfomation.SubSystemMajorVersion >= 3 && (SectionImageInfomation.SubSystemMajorVersion != 3 || SectionImageInfomation.SubSystemMinorVersion >= 10) && 
		SectionImageInfomation.SubSystemMajorVersion <= SharedUserData->NtMajorVersion && (SectionImageInfomation.SubSystemMajorVersion != SharedUserData->NtMajorVersion || SectionImageInfomation.SubSystemMinorVersion <= SharedUserData->NtMinorVersion))
	{
		//wprintf(L"[+] ImageVersion OK!\n");
		ImageVersionOk = TRUE;
	}
	if(!ImageVersionOk)
	{
		RtlSetLastWin32Error(ERROR_BAD_EXE_FORMAT);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	if (CreateInfo.SuccessState.u2.s2.ManifestDetected)
	{
		ManifestAddress = (PVOID)CreateInfo.SuccessState.ManifestAddress;
		ManifestSize = CreateInfo.SuccessState.ManifestSize;
	}

	Status = IsBasepCheckWebBladeHashesPresent() ? BasepCheckWebBladeHashes(FileHandle) : STATUS_SUCCESS;

	if (Status == STATUS_ACCESS_DENIED)
	{
		RtlSetLastWin32Error(ERROR_ACCESS_DISABLED_WEBBLADE);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	else if (!NT_SUCCESS(Status))
	{
		RtlSetLastWin32Error(ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	
	Status = IsBasepIsProcessAllowedPresent() ? BasepIsProcessAllowed((LPWSTR)lpApplicationName) : STATUS_SUCCESS;

	if (!NT_SUCCESS(Status))
	{
		BaseSetLastNTError(Status);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	if (!IsWowBinary && (dwCreationFlags & CREATE_SEPARATE_WOW_VDM))
		dwCreationFlags &= ~CREATE_SEPARATE_WOW_VDM;
	if (VdmBinaryType)
	{
		VdmWaitHandle = ProcessHandle;
		bStatus = IsBaseUpdateVDMEntryPresent() ? BaseUpdateVDMEntry(UPDATE_VDM_PROCESS_HANDLE, &VdmWaitHandle, VdmTaskId, VdmBinaryType) : FALSE;
		if (bStatus)
		{
			VdmCreationState |= VDM_FULLY_CREATED;
		}
		else
		{
			VdmWaitHandle = NULL;
			goto Leave_Cleanup;
		}
	}
	PebAddressNative = (PPEB)CreateInfo.SuccessState.PebAddressNative;
	if (!IsImageValidFixed && (dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL) == 0)
	{
		Status = IsBasepCheckWinSaferRestrictionsPresent() ? BasepCheckWinSaferRestrictions(CurrentTokenHandle, lpApplicationName, FileHandle, &PackageFullName) : STATUS_SUCCESS;
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	memset(&BaseCreateProcessMessage->Sxs, 0, sizeof(BaseCreateProcessMessage->Sxs));
	switch (SectionImageInfomation.Machine)
	{
		case IMAGE_FILE_MACHINE_I386:
			// If this is a .NET ILONLY that needs to run in a 64-bit addressspace, then let SXS be aware of this
			if (CreateInfo.SuccessState.u2.s2.AddressSpaceOverride)
				ImageProcessorArchitecture = SharedUserData->NativeProcessorArchitecture;
			else
				ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
			break;
		case IMAGE_FILE_MACHINE_ARMNT:
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM;
			break;
		case IMAGE_FILE_MACHINE_HYBRID_X86:
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_IA32_ON_WIN64;
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
			break;
		case IMAGE_FILE_MACHINE_ARM64:
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64;
			break;
		default:
			wprintf(L"[*] Kernel32: No mapping for ImageInformation.Machine == %04x\n", SectionImageInfomation.Machine);//DbgPrint_0
			ImageProcessorArchitecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
			break;
	}
	if (dwCreationFlags & CREATE_SECURE_PROCESS)
		goto ThreadResumePre;
	if (CreateInfo.SuccessState.u2.s2.ProtectedProcessLight && AppXProcessContext)
	{
		Status = NtQueryInformationProcess(ProcessHandle, ProcessProtectionInformation, &Protection, sizeof(PS_PROTECTION), NULL);
		if (!NT_SUCCESS(Status))
		{
			Status = STATUS_SUCCESS;
		}
		else if (Protection.Level == PsProtectedValue(PsProtectedSignerApp, FALSE, PsProtectedTypeProtectedLight))
		{
			//Type = PsProtectedTypeProtectedLight | Signer = PsProtectedSignerApp
			AppXProtectEnabled = TRUE;
		}
	}

	AppCompatImageMachine = 0;
	if ((!CreateInfo.SuccessState.u2.s2.ProtectedProcess || AppXProtectEnabled) && IsBasepQueryAppCompatPresent())
	{
		// kernel32.dll!CompatCacheLookupAndWriteToProcess->ntdll!NtApphelpCacheControl->ahcache.sys!AhcApiLookupAndWriteToProcess
		BasepQueryAppCompat(
			&SectionImageInfomation,
			CreateInfo.SuccessState.u2.s2.AddressSpaceOverride,
			ImageProcessorArchitecture,
			FileHandle,
			ProcessHandle,
			Win32ImagePath.Buffer,
			lpEnvironment,
			&PackageFullName,
			&SdbQueryResult,
			&SdbQueryResultSize,
			&AppCompatSxsData,
			&AppCompatSxsDataSize,
			&dwFusionFlags,
			&dwLuaRunlevelFlags,
			&dwInstallerFlags,
			&AppCompatImageMachine,
			&MaxVersionTested,
			&DeviceFamilyID
		);

		//
		// PackageOnly DEVICEFAMILYINFOENUM_DESKTOP = 3
		//
		// AppCompatSxsData: Manifest String Located in AppCompat (ShimDataBase *.sdb -- PDB[TAG_SXS_MANIFEST]）LPWSTR ? LPCSTR 
		// AppCompatSxsDataSize: ManifestLength * sizeof(WCHAR)
		// 
		// Allocate the string and return it. NOTE: SXS.DLL cannot handle
		// a NULL terminator at the end of the string. We must provide the
		// string without the NULL terminator.?
		//
		// MaxVersionTested = 0x000A | 0000 | 47BA | 0000 == 10.0.18362.0
		// RunlevelFlags ? dwFusionFlags ? dwInstallerFlags
		//
		wprintf(L"[*] %ls: SdbQueryResult        = 0x%p, SdbQueryResultSize   = %ld\n", BasepQueryAppCompatString, SdbQueryResult, SdbQueryResultSize);
		wprintf(L"[*] %ls: AppCompatSxsData      = 0x%p, AppCompatSxsDataSize = %ld\n", BasepQueryAppCompatString, AppCompatSxsData, AppCompatSxsDataSize);
		wprintf(L"[*] %ls: dwFusionFlags         = 0x%lx\n", BasepQueryAppCompatString, dwFusionFlags);
		wprintf(L"[*] %ls: dwLuaRunlevelFlags    = 0x%08llx\n", BasepQueryAppCompatString, dwLuaRunlevelFlags.FixFlag.QuadPart); //APPCOAMPAT_FLAG_LUA
		wprintf(L"[*] %ls: dwInstallerFlags      = 0x%lx\n", BasepQueryAppCompatString, dwInstallerFlags);
		wprintf(L"[*] %ls: AppCompatImageMachine = 0x%04x, DeviceFamilyID = %ld\n", BasepQueryAppCompatString, AppCompatImageMachine, DeviceFamilyID);//IMAGE_FILE_MACHINE_AMD64 DEVICEFAMILYINFOENUM_DESKTOP
		// win 11 26016 insider 26016/25019?
		if (dwLuaRunlevelFlags.LuaFlags.NoImageExpansion && (ProcessFlags & PROCESS_CREATE_FLAGS_IMAGE_EXPANSION_MITIGATION_DISABLE) == 0)
		{
			ProcessFlags |= PROCESS_CREATE_FLAGS_IMAGE_EXPANSION_MITIGATION_DISABLE;
			goto RetryNtCreateUserProcess;
		}
	}
	
	if (!CreateInfo.SuccessState.u2.s2.ProtectedProcess || CreateInfo.SuccessState.u2.s2.ProtectedProcessLight)
	{
		BaseCreateProcessMessage->Sxs.ProcessParameterFlags = CreateInfo.SuccessState.CurrentParameterFlags;
		if (IsBasepConstructSxsCreateProcessMessagePresent())
		{
			Status = BasepConstructSxsCreateProcessMessage(
				&NtImagePath,
				&Win32ImagePath,
				FileHandle,
				ProcessHandle,
				SectionHandle,
				CurrentTokenHandle,
				CreateInfo.SuccessState.u2.s2.DevOverrideEnabled,
				dwFusionFlags,
				AppCompatSxsData,
				AppCompatSxsDataSize,
				(SectionImageInfomation.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,
				(AppXProcessContext && !AppXProcessContext->u1.s1.AppXManifestDetected) ? AppXProcessContext->AppXCurrentDirectory : NULL,
				PebAddressNative,
				ManifestAddress,
				ManifestSize,
				&CreateInfo.SuccessState.CurrentParameterFlags,
				&BaseCreateProcessMessage->Sxs,
				&SxsCreateProcessUtilityStruct
			);

			if (!NT_SUCCESS(Status))
			{
				wprintf(L"[-] BasepConstructSxsCreateProcessMessage: 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		else
		{
			Status = STATUS_SUCCESS;
		}
	}
	BaseCreateProcessMessage->PebAddressWow64 = CreateInfo.SuccessState.PebAddressWow64;
	BaseCreateProcessMessage->PebAddressNative = CreateInfo.SuccessState.PebAddressNative;
	BaseCreateProcessMessage->ProcessHandle = ProcessHandle;
	BaseCreateProcessMessage->ThreadHandle = ThreadHandle;
	BaseCreateProcessMessage->ClientId = ClientId;
	BaseCreateProcessMessage->ProcessorArchitecture = ImageProcessorArchitecture;
	BaseCreateProcessMessage->CreationFlags = dwCreationFlags & ~(DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);//0x80040 | Remove debug flags now its not being done by CSR

	//
	// Set the 2 bit if a gui app is starting. The window manager needs to
	// know this so it can synchronize the startup of this app
	// (WaitForInputIdle api). This info is passed using the process
	// handle tag bits. The 1 bit asks the window manager to turn on
	// or turn off the application start cursor (hourglass/pointer).
	//
	// When starting a WOW process, lie and tell UserSrv NTVDM.EXE is a GUI
	// process.  We also turn on bit 0x8 so that UserSrv can ignore the
	// UserNotifyConsoleApplication call made by the console during startup.
	// 
	// BINARY_TYPE_WOW_EX | BINARY_TYPE_SEPWOW | BINARY_TYPE_WIN16
	//

	if (SectionImageInfomation.SubSystemType == IMAGE_SUBSYSTEM_WINDOWS_GUI || IsWowBinary)
	{

		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT);
		CurrentImageHeaders = RtlImageNtHeader(GetModuleHandleA(NULL));

		//
		// If the creating process is a GUI app, turn on the app. start cursor
		// by default.  This can be overridden by STARTF_FORCEOFFFEEDBACK.
		//

		if (CurrentImageHeaders && CurrentImageHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
		{
			BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);
		}
	}
	if (CurrentTokenHandle)
	{
		Status = NtQueryInformationToken(CurrentTokenHandle, TokenSessionId, &CurrentTokenSessionId, sizeof(ULONG), &Length);
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (CurrentTokenSessionId != NtCurrentPeb()->SessionId)
			BaseCreateProcessMessage->ThreadHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ThreadHandle | BASE_CREATE_PROCESS_MSG_THREAD_FLAG_CROSS_SESSION);
		CurrentTokenHandle = TokenHandle;
	}

	if (StartupInfo.dwFlags & STARTF_FORCEONFEEDBACK)
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);

	if (StartupInfo.dwFlags & STARTF_FORCEOFFFEEDBACK)
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle & ~BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);

	if (StartupInfo.dwFlags & STARTF_IGNOREGUIAPP)// [uncorrected] fontdrvhost.exe only?
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle & ~(BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT));

	BaseCreateProcessMessage->VdmBinaryType = VdmBinaryType;
	if (VdmBinaryType)
	{
		BaseCreateProcessMessage->hVDM = VdmTaskId ? 0 : BasepGetConsoleHost();
		BaseCreateProcessMessage->VdmTask = VdmTaskId;
	}
	if (CreateInfo.SuccessState.u2.s2.ProtectedProcess && !CreateInfo.SuccessState.u2.s2.ProtectedProcessLight)
		BaseCreateProcessMessage->ThreadHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ThreadHandle | BASE_CREATE_PROCESS_MSG_THREAD_FLAG_PROTECTED_PROCESS);

	if (BaseCreateProcessMessage->Sxs.Flags && !(BaseCreateProcessMessage->Sxs.Flags & BASE_MSG_SXS_NO_ISOLATION))
	{
		if (BaseCreateProcessMessage->Sxs.Flags & BASE_MSG_SXS_ALTERNATIVE_MODE)
		{
			CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Win32ImagePath;
			CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.NtImagePath;
			CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CultureFallBacks;
			CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyName;
			CaptureStringsCount = 4;
		}
		else
		{
			CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Manifest.Path;
			CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.Policy.Path;
			CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.AssemblyDirectory;
			CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.CultureFallBacks;
			CsrStringsToCapture[4] = &BaseCreateProcessMessage->Sxs.AssemblyName;
			CaptureStringsCount = 5;
		}
		Status = CsrCaptureMessageMultiUnicodeStringsInPlace(&CaptureBuffer, CaptureStringsCount, CsrStringsToCapture);
		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] CsrCaptureMessageMultiUnicodeStringsInPlace: 0x%08lx\n", Status);
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	//wprintf(L"[*] CaptureBuffer Heap Store: 0x%p, CaptureBuffer Length = %ld\n", CaptureBuffer, CaptureBuffer->Length);
	//BaseCreateProcessMessageOutPut(BaseCreateProcessMessage->Sxs);
	Status = CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage, CaptureBuffer, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess2), sizeof(BASE_CREATEPROCESS_MSG));
	if (!NT_SUCCESS((NTSTATUS)ApiMessage.Status))
	{
		wprintf(L"[-] CsrClientCallServer: 0x%08lx -- 0x%08lx\n", Status, ApiMessage.Status);
		BaseSetLastNTError((NTSTATUS)ApiMessage.Status);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}

	wprintf(L"------------------------------------------------------------------\n");
	BaseCreateProcessMessageOutPut(BaseCreateProcessMessage->Sxs);

	if (!CreateInfo.SuccessState.u2.s2.ProtectedProcess)
	{
		if (BaseCreateProcessMessage->Sxs.ProcessParameterFlags != CreateInfo.SuccessState.CurrentParameterFlags)
		{
			Status = BasepUpdateProcessParametersField(
				ProcessHandle,
				(LPVOID*)&BaseCreateProcessMessage->Sxs.ProcessParameterFlags,
				sizeof(ULONG),
				NULL,
				FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, Flags),// 0x8
				FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, Flags),// 0x8
				&CreateInfo);
			if (!NT_SUCCESS(Status))
			{
				wprintf(L"[-] BasepUpdateProcessParametersField: 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			wprintf(L"[*] Remote ProcessParameterFlags Updated: 0x%08lx -> 0x%08lx\n", CreateInfo.SuccessState.CurrentParameterFlags, BaseCreateProcessMessage->Sxs.ProcessParameterFlags);
		}
	}

	if (!IsBatchFile && !(ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_FORCELUA) && !SecurityCapabilities)
	{
		ElevationFlags |= ELEVATION_FLAG_TOKEN_CHECKS;
		Status = IsBaseCheckElevationPresent() ?
			BaseCheckElevation(
				ProcessHandle,
				FileHandle,
				Win32ImagePath.Buffer,
				&ElevationFlags,
				dwLuaRunlevelFlags,
				&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
				&BaseCreateProcessMessage->Sxs.AssemblyName,
				dwInstallerFlags,
				CurrentTokenHandle,
				NULL,
				NULL) : STATUS_SUCCESS;

		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] Elevation Check Error: 0x%08lx\n", Status);
			if (Status == STATUS_ELEVATION_REQUIRED && !(ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_ELEVATION_HANDLED) && IsBaseWriteErrorElevationRequiredEventPresent())
			{
				wprintf(L"[-] Process Elevation Required, ExtendedFlags = 0x%lx\n", ExtendedFlags);
				BaseWriteErrorElevationRequiredEvent();
			}
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	wprintf(L"[*] ElevationFlags = 0x%08lx\n", ElevationFlags);
	if (*BaseCreateProcessMessage->Sxs.ApplicationUserModelId && !PackageNameSpecified && !AppExecutionAliasInfo && !ActivationToken)
	{

		// 
		// kernel32.dll!AicGetPackageActivationTokenForSxS
		//   rpcrt4.dll!Ndr64AsyncClientCall:   CallRPC->0497B57D-2E66-424f-A0C6-157CD5D41700 [Proc: 3]
		//  appinfo.dll!RAiGetPackageActivationTokenForSxS
		//  appinfo.dll!CreateBnoIsolationPrefixForRpc
		//  appinfo.dll!CreateBnoIsolationPrefix
		//		GetPackageFamilyNameFromToken(ActivationToken, &packageFamilyNameLength, packageFamilyName)
		//		PackageSidFromFamilyName(packageFamilyName, &Sid)
		//		ConvertSidToStringSidW(Sid, BnoIsolationPrefix)
		//
		wprintf(L"[+] Package %ls Activation!\n", BaseCreateProcessMessage->Sxs.ApplicationUserModelId);
		Win32Error = BasepGetPackageActivationTokenForSxS(
			BaseCreateProcessMessage->Sxs.ApplicationUserModelId,
			TokenHandle,
			&ActivationToken);

		//
		// TEST ActivationTokenInfo.BnoIsolationPackageSidString is NOT cleaned correctly yet.
		//
		if (Win32Error == ERROR_CALL_NOT_IMPLEMENTED)
		{
			Win32Error = BasepGetPackageActivationTokenForSxS2(
				BaseCreateProcessMessage->Sxs.ApplicationUserModelId,
				TokenHandle,
				&ActivationTokenInfo);
			ActivationToken = ActivationTokenInfo.ActivationTokenHandle;
		}
		else
		{
			ActivationTokenInfo.ActivationTokenHandle = ActivationToken;
		}
		
		if (Win32Error != ERROR_SUCCESS)
		{
			RtlSetLastWin32Error(Win32Error);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		
		if (ActivationTokenInfo.ActivationTokenHandle)
		{
			UINT32 packageFullNameLength = PACKAGE_FULL_NAME_MAX_LENGTH + 1;
			Win32Error = GetPackageFullNameFromToken_(
				ActivationTokenInfo.ActivationTokenHandle,
				&packageFullNameLength,
				packageFullName);

			if (Win32Error != ERROR_SUCCESS)
			{
				Status = STATUS_UNSUCCESSFUL;
				RtlSetLastWin32Error(Win32Error);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			RtlInitUnicodeString(&PackageFullName, packageFullName);

			if (OSBuildNumber >= 25357 && ActivationTokenInfo.PackageBnoIsolationPrefix)
			{
				RtlInitUnicodeString(&BnoIsolation.IsolationPrefix, ActivationTokenInfo.PackageBnoIsolationPrefix);
				BnoIsolation.IsolationEnabled = TRUE;
				AppXPackageBnoIsolationDetected = TRUE;
			}
			goto RetryNtCreateUserProcess;
		}
	}

	if (CreateInfo.SuccessState.u2.s2.ProtectedProcess)
	{
		if (AppXProtectEnabled && IsBasepGetAppCompatDataPresent())
		{
			wprintf(L"[!] AppXProtect SafeMode AppCompatData Write.\n");
			
			BasepGetAppCompatData(
				Win32ImagePath.Buffer,
				PackageFullName.Buffer,
				&ElevationFlags,
				&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
				&BaseCreateProcessMessage->Sxs.SxsSupportOSInfo,
				&BaseCreateProcessMessage->Sxs.SxsMaxVersionTested,
				&SectionImageInfomation,
				AppCompatImageMachine,
				MaxVersionTested.MaxVersionTested,
				DeviceFamilyID,
				&SdbQueryResult,
				&SdbQueryResultSize,
				&AppCompatData,
				&AppCompatDataSize);

			wprintf(L"[!] NtApphelpCacheControl->AhcApiInitProcessData.\n");
			//wprintf(L"[!] Require NtCurrentProcessToken()->TokenUser == SYSTEM, +SeTcbPrivilege, TargetProcess AppXProtect && IsPackageProcess!\n");
			if (!BasepInitAppCompatData(ProcessHandle, AppCompatData, AppCompatDataSize))
			{
				//AhcApiInitProcessData Fail Due to: (No SeTcbPrivilege || No AppXProtect || No PackageProcess)
				BaseSetLastNTError(STATUS_ACCESS_DENIED);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
	}
	else if (IsBasepGetAppCompatDataPresent())
	{
		wprintf(L"[*] Normal AppCompatData Write.\n");
		BasepGetAppCompatData(
			Win32ImagePath.Buffer,
			PackageFullName.Buffer,
			&ElevationFlags,//a3
			&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
			&BaseCreateProcessMessage->Sxs.SxsSupportOSInfo,
			&BaseCreateProcessMessage->Sxs.SxsMaxVersionTested,
			&SectionImageInfomation,
			AppCompatImageMachine,
			MaxVersionTested.MaxVersionTested,
			DeviceFamilyID,
			&SdbQueryResult,
			&SdbQueryResultSize,
			&AppCompatData,
			&AppCompatDataSize);
		
		if (AppCompatData)
		{
			
			PVOID pAppCompatDataInNewProcess = 0;
			RegionSize = AppCompatDataSize;
			Status = NtAllocateVirtualMemory(ProcessHandle, &pAppCompatDataInNewProcess, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
			if (!NT_SUCCESS(Status)) {
				wprintf(L"[-] Fail on NtAllocateVirtualMemory: pAppCompatDataInNewProcess: 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			Status = NtWriteVirtualMemory(
				ProcessHandle,
				pAppCompatDataInNewProcess,
				AppCompatData,
				AppCompatDataSize,
				NULL);
			if (!NT_SUCCESS(Status)) {
				wprintf(L"[-] Fail on NtWriteVirtualMemory: pAppCompatDataInNewProcess: 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}

			Status = NtWriteVirtualMemory(
				ProcessHandle,
				&PebAddressNative->pShimData,
				&pAppCompatDataInNewProcess,
				sizeof(PVOID),
				NULL);
			if (!NT_SUCCESS(Status)) {
				wprintf(L"[-] Fail on NtWriteVirtualMemory: Peb->pShimData: 0x%08lx\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}

			wprintf(L"[*] %ls: AppCompatData  = 0x%p, AppCompatDataSize  = %ld Written via UserMode.\n", BasepGetAppCompatDataString, AppCompatData, AppCompatDataSize);
			wprintf(L"[*] %ls: SdbQueryResult = 0x%p, SdbQueryResultSize = %ld\n", BasepGetAppCompatDataString, SdbQueryResult, SdbQueryResultSize);
			wprintf(L"[*] Already Located in RemoteProcess Peb->pShimData: 0x%p, Data RemotePointer: 0x%p\n", &PebAddressNative->pShimData, pAppCompatDataInNewProcess);

			if (CreateInfo.SuccessState.PebAddressWow64)
			{
				ULONG pAppCompatDataInNewProcessWow64 = PtrToUlong(pAppCompatDataInNewProcess);
				Status = NtWriteVirtualMemory(
					ProcessHandle,
					&ULongToPeb32Ptr(CreateInfo.SuccessState.PebAddressWow64)->pShimData,// ULongToPtr(CreateInfo.SuccessState.PebAddressWow64 + FIELD_OFFSET(PEB32, pShimData))
					&pAppCompatDataInNewProcessWow64,
					sizeof(ULONG),
					NULL);
				if (!NT_SUCCESS(Status)) {
					wprintf(L"[-] Fail on NtWriteVirtualMemory: Peb32->pShimData (Wow64): 0x%08lx\n", Status);
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
		}
	}

	if (!IsBatchFile && !CreateInfo.SuccessState.u2.s2.ProtectedProcess)
	{
		Status = IsBaseElevationPostProcessingPresent() ? BaseElevationPostProcessing(ElevationFlags, ImageProcessorArchitecture, ProcessHandle) : STATUS_SUCCESS;
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	if (AppXProcessContext)
	{
		Status = BasepPostSuccessAppXExtension(ProcessHandle, AppXProcessContext);// kernelbase.dll!AppXPostSuccessExtension
		wprintf(L"[*] BasepPostSuccessAppXExtension: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (AppXProcessContext->RemoteBaseAddress)
		{
			Status = BasepUpdateProcessParametersField(
				ProcessHandle,
				&AppXProcessContext->RemoteBaseAddress, //PackageDependencyData
				sizeof(PVOID),
				NULL,
				FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, PackageDependencyData), // 0x400
				FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, PackageDependencyData),// 0x298
				&CreateInfo);
			
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			wprintf(L"[*] Remote PackageDependencyData Updated: 0x%p\n", AppXProcessContext->RemoteBaseAddress);
		}
		ActivationFlag = 0;
		if(lpExtendedPackagedAppContext)
		{
			if (lpExtendedPackagedAppContext->AppType != GeneralUWPApp)
			{
				Win32Error = CompletePackagedProcessCreationEx(
					ProcessHandle,
					ThreadHandle,
					lpExtendedPackagedAppContext->AppType == ConsoleUWPApp,
					lpExtendedPackagedAppContext->AppType == MultipleInstancesUWPApp,
					lpCurrentDirectory,
					lpCommandLine,
					lpExtendedPackagedAppContext->IsAppExecutionAliasType,
					CurrentTokenHandle,
					&ActivationFlag);

				if (Win32Error != 0)
				{
					RtlSetLastWin32Error(Win32Error);
					Status = STATUS_UNSUCCESSFUL;
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			
		}
		else if (AppExecutionAliasInfo && (AppExecutionAliasInfo->BreakawayModeLaunch != TRUE))
		{
			// BOOL NormalCompleteAppExecutionAliasProcessCreation = TRUE; // ETW: 
			Status = CompleteAppExecutionAliasProcessCreationEx(
				ProcessHandle,
				ThreadHandle,
				AppExecutionAliasInfo->BreakawayModeLaunch,
				lpCurrentDirectory,
				lpCommandLine,
				CurrentTokenHandle,
				&ActivationFlag);

			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		else if (ActivationToken != NULL)
		{
			Win32Error = BasepFinishPackageActivationForSxS(
				ProcessHandle,
				ThreadHandle,
				lpCurrentDirectory,
				lpCommandLine,
				CurrentTokenHandle,
				&ActivationFlag);

			if (Win32Error != 0)
			{
				RtlSetLastWin32Error(Win32Error);
				Status = STATUS_UNSUCCESSFUL;
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		if (ActivationFlag & APPX_PACKEAGE_CREATEION_SUSPEND)
			dwCreationFlags |= CREATE_SUSPENDED;
	}
ThreadResumePre:
	if (!(dwCreationFlags & CREATE_SUSPENDED))
	{
		Status = NtResumeThread(ThreadHandle, NULL);
		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] NtResumeThread: 0x%08lx\n", Status);
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		wprintf(L"[+] Thread Resumed!\n");
	}
FinalSuccess:
	bStatus = TRUE;
	if (VdmCreationState)
		VdmCreationState |= VDM_CREATION_SUCCESSFUL;
	if (VdmWaitHandle)
	{
		//
		// tag Shared WOW VDM handles so that wait for input idle has a
		// chance to work. Shared WOW VDM "process" handles are actually
		// event handles. Separate WOW VDM handles are real process
		// handles. Also mark DOS handles with 0x1 so WaitForInputIdle
		// has a way to distinguish DOS apps and not block forever.
		//

		if (VdmBinaryType == BINARY_TYPE_WIN16)
		{
			lpProcessInformation->hProcess = (HANDLE)((ULONG_PTR)VdmWaitHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT);
			if (VdmCreationState & VDM_BEING_REUSED)
			{

				//
				// Shared WOW doesn't always start a process, so
				// we don't have a process ID or thread ID to
				// return if the VDM already existed.
				//
				// Separate WOW doesn't hit this codepath
				// (no VdmWaitHandle).
				//

				ClientId.UniqueProcess = 0;
				ClientId.UniqueThread = 0;
			}
		}
		else
		{
			lpProcessInformation->hProcess = (HANDLE)((ULONG_PTR)VdmWaitHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);
		}
		if (ProcessHandle)
			NtClose(ProcessHandle);
	}
	else
	{
		lpProcessInformation->hProcess = ProcessHandle;
	}
	lpProcessInformation->hThread = ThreadHandle;
	lpProcessInformation->dwProcessId = HandleToUlong(ClientId.UniqueProcess);
	lpProcessInformation->dwThreadId = HandleToUlong(ClientId.UniqueThread);
	ProcessHandle = NULL;
	ThreadHandle = NULL;

Leave_Cleanup:
	LastErrorValue = NtCurrentTeb()->LastErrorValue;

	if (ImageFileDebuggerCommand)
		RtlFreeHeap(RtlProcessHeap(), 0, ImageFileDebuggerCommand);

	if (ExePathFullBuffer)
		RtlFreeHeap(RtlProcessHeap(), 0, ExePathFullBuffer);

	RtlFreeUnicodeString(&NtImagePath);

	if (!VdmBinaryType && IsBasepReleaseSxsCreateProcessUtilityStructPresent())
	{
		BasepReleaseSxsCreateProcessUtilityStruct(&SxsCreateProcessUtilityStruct);
	}

	if (UnicodeEnvironment)
		RtlDestroyEnvironment(UnicodeEnvironment);

	if (AppExecutionAliasInfo) //ETW Event..........
	{
		// EVENT_DATA_DESCRIPTOR EventUserData[15]
		// EtwEventWriteTransfer
		// .......................

		if (!bStatus) //Fail
		{
			PerformAppxLicenseRundownEx(AppExecutionAliasInfo->AppXPackageName, AppExecutionAliasInfo->TokenHandle);
		}
		FreeAppExecutionAliasInfoEx(AppExecutionAliasInfo);
	}

	if (AppXProcessContext)
	{
		BasepReleaseAppXContext(AppXProcessContext);
		AppXProcessContext = NULL;
	}

	if (AppXContent)
		BasepReleaseAppXContext(AppXContent);
	if (LowBoxToken)
		NtClose(LowBoxToken);
	if (ActivationToken)
		NtClose(ActivationToken);
	if (AppXEnvironment)
		RtlDestroyEnvironment(AppXEnvironment);
	if (QuotedCmdLine)
		RtlFreeHeap(RtlProcessHeap(), 0, QuotedCmdLine);
	if (NameBuffer)
		RtlFreeHeap(RtlProcessHeap(), 0, NameBuffer);
	if (NewCommandLine)
		RtlFreeHeap(RtlProcessHeap(), 0, NewCommandLine);
	if (CurrentDirectoryHeap)
		RtlFreeHeap(RtlProcessHeap(), 0, CurrentDirectoryHeap);
	if (FileHandle)
		NtClose(FileHandle);
	if (SectionHandle)
		NtClose(SectionHandle);

	if (ThreadHandle)
	{
		if (DebugPortHandle)
			NtRemoveProcessDebug(ProcessHandle, DebugPortHandle);
		NtTerminateProcess(ProcessHandle, Status);
		NtWaitForSingleObject(ProcessHandle, FALSE, NULL);
		NtClose(ThreadHandle);
		wprintf(L"[!] Process Terminated!\n");
	}
	if (ProcessHandle)
		NtClose(ProcessHandle);

	if (IsBasepFreeAppCompatDataPresent())
		BasepFreeAppCompatData(AppCompatData, AppCompatSxsData, SdbQueryResult);

	RtlFreeUnicodeString(&SubSysCommandLine);

	if ((AnsiStringVDMEnv.Buffer || UnicodeStringVDMEnv.Buffer) && IsBaseDestroyVDMEnvironmentPresent())
		BaseDestroyVDMEnvironment(&AnsiStringVDMEnv, &UnicodeStringVDMEnv);

	if (VdmCreationState && !(VdmCreationState & VDM_CREATION_SUCCESSFUL))
	{
		if (IsBaseUpdateVDMEntryPresent())
			BaseUpdateVDMEntry(UPDATE_VDM_UNDO_CREATION, (HANDLE*)&VdmTaskId, VdmCreationState, VdmBinaryType);
		if (VdmWaitHandle)
			NtClose(VdmWaitHandle);
	}

	if (PathToSearch)
		RtlReleasePath(PathToSearch);

	if (CaptureBuffer)
	{
		CsrFreeCaptureBuffer(CaptureBuffer);
		CaptureBuffer = NULL;
	}

	if (AppXAliasCommandline)
		RtlFreeHeap(RtlProcessHeap(), 0, AppXAliasCommandline);

	if(PackageNewCommandLine)
		RtlFreeHeap(RtlProcessHeap(), 0, PackageNewCommandLine);

	if (lpExtendedPackagedAppContext)//21332
	{
		BasepReleasePackagedAppInfo(lpExtendedPackagedAppContext);
		lpExtendedPackagedAppContext = NULL;
	}
	BasepFreeBnoIsolationParameter(&BnoIsolation);
	BasepFreeActivationTokenInfo(&ActivationTokenInfo);
	NtCurrentTeb()->LastErrorValue = LastErrorValue;
	wprintf(L"[*] Clean up done.\n");
	return bStatus;
}