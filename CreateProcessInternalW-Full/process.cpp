#include <ntstatus.h>
#include <strsafe.h>
#include "ntapi.hpp"
#include "otherapi.hpp"
#include "csrss.hpp"
#include "syscalls.hpp"

HMODULE ntvdm64 = 0;
NtVdm64CreateProcessInternalW_ NtVdm64CreateProcessInternalW = NULL;

CsrCaptureMessageMultiUnicodeStringsInPlace_ CsrCaptureMessageMultiUnicodeStringsInPlace;
CsrClientCallServer_ CsrClientCallServer;
DbgUiConnectToDbg_ DbgUiConnectToDbg;
DbgUiGetThreadDebugObject_ DbgUiGetThreadDebugObject;
RtlSetLastWin32Error_ RtlSetLastWin32Error;
RtlGetExePath_ RtlGetExePath;
RtlReleasePath_ RtlReleasePath;
RtlInitUnicodeString_ RtlInitUnicodeString;
RtlInitUnicodeStringEx_ RtlInitUnicodeStringEx;
RtlFreeUnicodeString_ RtlFreeUnicodeString;
RtlDosPathNameToNtPathName_U_ RtlDosPathNameToNtPathName_U;
RtlDetermineDosPathNameType_U_ RtlDetermineDosPathNameType_U;
RtlGetFullPathName_UstrEx_ RtlGetFullPathName_UstrEx;
RtlIsDosDeviceName_U_ RtlIsDosDeviceName_U;
RtlAllocateHeap_ RtlAllocateHeap;
RtlFreeHeap_ RtlFreeHeap;
RtlCreateEnvironmentEx_ RtlCreateEnvironmentEx;
RtlImageNtHeader_ RtlImageNtHeader;
RtlDestroyEnvironment_ RtlDestroyEnvironment;
RtlWow64GetProcessMachines_ RtlWow64GetProcessMachines;
RtlDestroyProcessParameters_ RtlDestroyProcessParameters;
LdrQueryImageFileKeyOption_ LdrQueryImageFileKeyOption;
RtlGetVersion_ RtlGetVersion;
CsrFreeCaptureBuffer_ CsrFreeCaptureBuffer;
KernelBaseGetGlobalData_ KernelBaseGetGlobalData;
BaseFormatObjectAttributes_ BaseFormatObjectAttributes;
CheckAppXPackageBreakaway_ CheckAppXPackageBreakaway;
LoadAppExecutionAliasInfoEx_ LoadAppExecutionAliasInfoEx;
GetAppExecutionAliasPath_ GetAppExecutionAliasPath;
CompleteAppExecutionAliasProcessCreationEx_ CompleteAppExecutionAliasProcessCreationEx;
PerformAppxLicenseRundownEx_ PerformAppxLicenseRundownEx;
FreeAppExecutionAliasInfoEx_ FreeAppExecutionAliasInfoEx;
GetEmbeddedImageMitigationPolicy_ GetEmbeddedImageMitigationPolicy;
BaseSetLastNTError_ BaseSetLastNTError;
BasepAppXExtension_ BasepAppXExtension;
BasepConstructSxsCreateProcessMessage_ BasepConstructSxsCreateProcessMessage;
BasepAppContainerEnvironmentExtension_ BasepAppContainerEnvironmentExtension;
BasepFreeAppCompatData_ BasepFreeAppCompatData;
BasepReleaseAppXContext_ BasepReleaseAppXContext;
BasepReleaseSxsCreateProcessUtilityStruct_ BasepReleaseSxsCreateProcessUtilityStruct;
BasepCheckWebBladeHashes_ BasepCheckWebBladeHashes;
BasepIsProcessAllowed_ BasepIsProcessAllowed;
BaseUpdateVDMEntry_ BaseUpdateVDMEntry;
BasepProcessInvalidImage_ BasepProcessInvalidImage;
RaiseInvalid16BitExeError_ RaiseInvalid16BitExeError;
BaseIsDosApplication_ BaseIsDosApplication;
BasepCheckWinSaferRestrictions_ BasepCheckWinSaferRestrictions;
BasepQueryAppCompat_ BasepQueryAppCompat;
BasepGetAppCompatData_ BasepGetAppCompatData;
BasepInitAppCompatData_ BasepInitAppCompatData;
BaseWriteErrorElevationRequiredEvent_ BaseWriteErrorElevationRequiredEvent;
BaseCheckElevation_ BaseCheckElevation;
BasepGetPackageActivationTokenForSxS_ BasepGetPackageActivationTokenForSxS;
BaseElevationPostProcessing_ BaseElevationPostProcessing;
BasepPostSuccessAppXExtension_ BasepPostSuccessAppXExtension;
BasepFinishPackageActivationForSxS_ BasepFinishPackageActivationForSxS;
BaseDestroyVDMEnvironment_ BaseDestroyVDMEnvironment;

//OSVERSIONINFOEXW lpVersionInformation = { 0 };

NTSTATUS ValidateAppExecutionAliasRedirectPackageIdentity(HANDLE KeyHandle, ExtendedAppExecutionAliasInfo_New* AppExecutionAliasInfo)
{
	NTSTATUS Status; // ebx
	//wchar_t* i; // rcx
	wchar_t* SplitBuffer; // rax
	ULONG ReturnedLength; // [rsp+30h] [rbp-B8h] BYREF
	wchar_t* Context; // [rsp+38h] [rbp-B0h] BYREF
	WCHAR Buffer[72] = { 0 }; // [rsp+40h] [rbp-A8h] BYREF

	Status = LdrQueryImageFileKeyOption(KeyHandle, L"AppExecutionAliasRedirectPackages", REG_SZ, Buffer, 130, &ReturnedLength);
	Buffer[64] = 0;
	if (!NT_SUCCESS(Status))
		return Status;
	if (ReturnedLength >= 4)
	{
		if (Buffer[0] == '*' && !Buffer[1])
		{
			return 0;
		}
		else
		{
			Status = STATUS_ACCESS_DENIED;
			Context = 0;
			SplitBuffer = wcstok_s(Buffer, L";", &Context);

			while (SplitBuffer)
			{
				SplitBuffer = wcstok_s(NULL, L";", &Context);
				if (CompareStringOrdinal(SplitBuffer, -1, AppExecutionAliasInfo->AppExecutionAliasRedirectPackages, -1, 1) == CSTR_EQUAL)
					return STATUS_SUCCESS;
			}
		}
	}
	else
	{
		Status =  STATUS_ACCESS_DENIED;
	}
	return Status;
	
}
void init()
{
	SW3_PopulateSyscallList();//Init  ovo..
	HMODULE AppExecutionAlias = LoadLibraryW(L"ApiSetHost.AppExecutionAlias.dll");
	HMODULE daxexec = LoadLibraryW(L"daxexec.dll");
	HMODULE sechost = GetModuleHandleW(L"sechost.dll");
	HMODULE ntdll = (HMODULE)Ntdll;
	HMODULE kernel32 = (HMODULE)Kernel32;
	HMODULE kernelbase = (HMODULE)KernelBase;
	if (AppExecutionAlias && daxexec && sechost)
	{

		CheckAppXPackageBreakaway = (CheckAppXPackageBreakaway_)GetProcAddress(daxexec, "CheckAppXPackageBreakaway");
		LoadAppExecutionAliasInfoEx = (LoadAppExecutionAliasInfoEx_)GetProcAddress(AppExecutionAlias, "LoadAppExecutionAliasInfoEx");
		GetAppExecutionAliasPath = (GetAppExecutionAliasPath_)GetProcAddress(AppExecutionAlias, "GetAppExecutionAliasPath");
		CompleteAppExecutionAliasProcessCreationEx = (CompleteAppExecutionAliasProcessCreationEx_)GetProcAddress(AppExecutionAlias, "CompleteAppExecutionAliasProcessCreationEx");
		PerformAppxLicenseRundownEx = (PerformAppxLicenseRundownEx_)GetProcAddress(AppExecutionAlias, "PerformAppxLicenseRundownEx");
		FreeAppExecutionAliasInfoEx = (FreeAppExecutionAliasInfoEx_)GetProcAddress(AppExecutionAlias, "FreeAppExecutionAliasInfoEx");
		GetEmbeddedImageMitigationPolicy = (GetEmbeddedImageMitigationPolicy_)GetProcAddress(sechost, "GetEmbeddedImageMitigationPolicy");
	}
	else
	{
		wprintf(L"[-] Error in Module Load...\n");
	}
	CsrCaptureMessageMultiUnicodeStringsInPlace = (CsrCaptureMessageMultiUnicodeStringsInPlace_)GetProcAddress(ntdll, "CsrCaptureMessageMultiUnicodeStringsInPlace");
	CsrClientCallServer = (CsrClientCallServer_)GetProcAddress(ntdll, "CsrClientCallServer");
	DbgUiConnectToDbg = (DbgUiConnectToDbg_)GetProcAddress(ntdll, "DbgUiConnectToDbg");
	DbgUiGetThreadDebugObject = (DbgUiGetThreadDebugObject_)GetProcAddress(ntdll, "DbgUiGetThreadDebugObject");
	RtlSetLastWin32Error = (RtlSetLastWin32Error_)GetProcAddress(ntdll, "RtlSetLastWin32Error");
	RtlGetExePath = (RtlGetExePath_)GetProcAddress(ntdll, "RtlGetExePath");
	RtlReleasePath = (RtlReleasePath_)GetProcAddress(ntdll, "RtlReleasePath");
	RtlInitUnicodeString = (RtlInitUnicodeString_)GetProcAddress(ntdll, "RtlInitUnicodeString");
	RtlInitUnicodeStringEx = (RtlInitUnicodeStringEx_)GetProcAddress(ntdll, "RtlInitUnicodeStringEx");
	RtlFreeUnicodeString = (RtlFreeUnicodeString_)GetProcAddress(ntdll, "RtlFreeUnicodeString");
	RtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U_)GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U");
	RtlDetermineDosPathNameType_U = (RtlDetermineDosPathNameType_U_)GetProcAddress(ntdll, "RtlDetermineDosPathNameType_U");
	RtlGetFullPathName_UstrEx = (RtlGetFullPathName_UstrEx_)GetProcAddress(ntdll, "RtlGetFullPathName_UstrEx");
	RtlIsDosDeviceName_U = (RtlIsDosDeviceName_U_)GetProcAddress(ntdll, "RtlIsDosDeviceName_U");
	RtlAllocateHeap = (RtlAllocateHeap_)GetProcAddress(ntdll, "RtlAllocateHeap");
	RtlFreeHeap = (RtlFreeHeap_)GetProcAddress(ntdll, "RtlFreeHeap");
	RtlCreateEnvironmentEx = (RtlCreateEnvironmentEx_)GetProcAddress(ntdll, "RtlCreateEnvironmentEx");
	RtlImageNtHeader = (RtlImageNtHeader_)GetProcAddress(ntdll, "RtlImageNtHeader");
	RtlDestroyEnvironment = (RtlDestroyEnvironment_)GetProcAddress(ntdll, "RtlDestroyEnvironment");
	RtlWow64GetProcessMachines = (RtlWow64GetProcessMachines_)GetProcAddress(ntdll, "RtlWow64GetProcessMachines");
	RtlDestroyProcessParameters = (RtlDestroyProcessParameters_)GetProcAddress(ntdll, "RtlDestroyProcessParameters");
	LdrQueryImageFileKeyOption = (LdrQueryImageFileKeyOption_)GetProcAddress(ntdll, "LdrQueryImageFileKeyOption");
	RtlGetVersion = (RtlGetVersion_)GetProcAddress(ntdll, "RtlGetVersion");
	CsrFreeCaptureBuffer = (CsrFreeCaptureBuffer_)GetProcAddress(ntdll, "CsrFreeCaptureBuffer");

	KernelBaseGetGlobalData = (KernelBaseGetGlobalData_)GetProcAddress(kernelbase, "KernelBaseGetGlobalData");
	BaseFormatObjectAttributes = (BaseFormatObjectAttributes_)GetProcAddress(kernelbase, "BaseFormatObjectAttributes");


	BaseSetLastNTError = (BaseSetLastNTError_)GetProcAddress(kernel32, "BaseSetLastNTError");
	BasepAppXExtension = (BasepAppXExtension_)GetProcAddress(kernel32, "BasepAppXExtension");
	BasepConstructSxsCreateProcessMessage = (BasepConstructSxsCreateProcessMessage_)GetProcAddress(kernel32, "BasepConstructSxsCreateProcessMessage");
	BasepAppContainerEnvironmentExtension = (BasepAppContainerEnvironmentExtension_)GetProcAddress(kernel32, "BasepAppContainerEnvironmentExtension");
	BasepFreeAppCompatData = (BasepFreeAppCompatData_)GetProcAddress(kernel32, "BasepFreeAppCompatData");
	BasepReleaseAppXContext = (BasepReleaseAppXContext_)GetProcAddress(kernel32, "BasepReleaseAppXContext");
	BasepReleaseSxsCreateProcessUtilityStruct = (BasepReleaseSxsCreateProcessUtilityStruct_)GetProcAddress(kernel32, "BasepReleaseSxsCreateProcessUtilityStruct");
	BasepCheckWebBladeHashes = (BasepCheckWebBladeHashes_)GetProcAddress(kernel32, "BasepCheckWebBladeHashes");
	BasepIsProcessAllowed = (BasepIsProcessAllowed_)GetProcAddress(kernel32, "BasepIsProcessAllowed");
	BaseUpdateVDMEntry = (BaseUpdateVDMEntry_)GetProcAddress(kernel32, "BaseUpdateVDMEntry");
	BasepProcessInvalidImage = (BasepProcessInvalidImage_)GetProcAddress(kernel32, "BasepProcessInvalidImage");
	RaiseInvalid16BitExeError = (RaiseInvalid16BitExeError_)GetProcAddress(kernel32, "RaiseInvalid16BitExeError");
	BaseIsDosApplication = (BaseIsDosApplication_)GetProcAddress(kernel32, "BaseIsDosApplication");
	BasepCheckWinSaferRestrictions = (BasepCheckWinSaferRestrictions_)GetProcAddress(kernel32, "BasepCheckWinSaferRestrictions");
	BasepQueryAppCompat = (BasepQueryAppCompat_)GetProcAddress(kernel32, "BasepQueryAppCompat");
	BasepGetAppCompatData = (BasepGetAppCompatData_)GetProcAddress(kernel32, "BasepGetAppCompatData");
	BasepInitAppCompatData = (BasepInitAppCompatData_)GetProcAddress(kernel32, "BasepInitAppCompatData");
	BaseWriteErrorElevationRequiredEvent = (BaseWriteErrorElevationRequiredEvent_)GetProcAddress(kernel32, "BaseWriteErrorElevationRequiredEvent");
	BaseCheckElevation = (BaseCheckElevation_)GetProcAddress(kernel32, "BaseCheckElevation");
	BasepGetPackageActivationTokenForSxS = (BasepGetPackageActivationTokenForSxS_)GetProcAddress(kernel32, "BasepGetPackageActivationTokenForSxS");
	BaseElevationPostProcessing = (BaseElevationPostProcessing_)GetProcAddress(kernel32, "BaseElevationPostProcessing");
	BasepPostSuccessAppXExtension = (BasepPostSuccessAppXExtension_)GetProcAddress(kernel32, "BasepPostSuccessAppXExtension");
	BasepFinishPackageActivationForSxS = (BasepFinishPackageActivationForSxS_)GetProcAddress(kernel32, "BasepFinishPackageActivationForSxS");
	BaseDestroyVDMEnvironment = (BaseDestroyVDMEnvironment_)GetProcAddress(kernel32, "BaseDestroyVDMEnvironment");
	RtlSetLastWin32Error(0);
}

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
    PHANDLE hRestrictedUserToken //????????????????
    ) 
{
	//unresolved external symbol ... **** *** **
	init();
	RtlGetDeviceFamilyInfoEnum_ RtlGetDeviceFamilyInfoEnum = (RtlGetDeviceFamilyInfoEnum_)GetProcAddress((HMODULE)Ntdll, "RtlGetDeviceFamilyInfoEnum");
	GetPackageFullNameFromToken_ GetPackageFullNameFromToken = (GetPackageFullNameFromToken_)GetProcAddress((HMODULE)KernelBase, "GetPackageFullNameFromToken");

	BOOL bStatus = FALSE;
	NTSTATUS Status = 0;
	NTSTATUS AliasStatus = 0;
	NTSTATUS SaferStatus = 0;
	ULONG Win32Error = 0;
	CHAR PriorityClass = 0;
	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;
	HANDLE DebugPortHandle = NULL;
	PS_PROTECTION Protection = { 0 };
	BOOLEAN AppXProtectEnabled = FALSE;
	PS_TRUSTLET_CREATE_ATTRIBUTES TrustletCreateAttributes = { 0 };
	PS_CREATE_INFO CreateInfo = { 0 };
	PS_ATTRIBUTE_LIST AttributeList = { 0 };
	PS_ATTRIBUTE_LIST AttributeListTemp = { 0 };
	ULONG AttributeListCount = 0;
	ULONG AttributeListTempCount = 0;
	SIZE_T TotalLength = 0;

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
	PWSTR UnicodeEnvironment = 0;
	STARTUPINFOEXW ExtendStartupInfo = { 0 };
	STARTUPINFOW StartInfo = { 0 };
	LPWSTR FilePart = 0;
	LPWSTR CurrentDirectoryHeap = NULL;
	PWSTR AppExecutionAliasPathHeap = NULL;
	PWSTR AliasPathHeap = NULL;
	DWORD FullPathNameLength = 0;
	OBJECT_ATTRIBUTES LocalProcessObjectAttribute = { 0 };
	OBJECT_ATTRIBUTES LocalThreadObjectAttribute = { 0 };
	POBJECT_ATTRIBUTES ProcessObjectAttributes = { 0 };
	POBJECT_ATTRIBUTES ThreadObjectAttributes = { 0 };
	BOOL DefaultInheritOnly = FALSE;
	HANDLE ActivationToken = NULL;
	PWSTR ExePathFullBuffer = NULL;
	LPWSTR QuotedCmdLine = NULL;
	HANDLE FileHandle = NULL;
	HANDLE SectionHandle = NULL;
	HANDLE LowBoxTokenHandle = NULL;
	PVOID AppCompatData = NULL;
	DWORD AppCompatDataSize = 0;
	PVOID AppCompatSxsData = NULL;
	DWORD AppCompatSxsDataSize = 0;
	PVOID AppCompatCacheData = NULL;
	DWORD AppCompatCacheDataSize = 0;
	BOOL AppCompatSxsSafeMode = 0;
	ULONGLONG AppCompatPrivilegeFlags = 0;
	DWORD UnknowCompatCache3 = 0;
	DWORD ElevationFlags = 0;

	USHORT AppCompatImageMachine = 0;
	DWORD DeviceFamilyID = 0; //DEVICEFAMILYINFOENUM_DESKTOP = 3

	HANDLE VdmWaitHandle = NULL;
	ANSI_STRING AnsiStringVDMEnv = { 0 };
	UNICODE_STRING UnicodeStringVDMEnv = { 0 };
	ULONG VdmCreationState = 0;
	ULONG VdmBinaryType = 0;
	ULONG VdmTaskId = 0;
	BOOL VdmPartiallyCreated = FALSE;
	BOOLEAN bSaferChecksNeeded = FALSE;
	BOOLEAN QueryImageFileKeyFailPresent = FALSE;
	PWSTR ImageFileDebuggerCommand = NULL;
	BOOL AppAliasRedirect = FALSE;

	HANDLE IFEOKey = NULL;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = { 0 };
	ULONG ExtendedFlags = 0;
	BOOLEAN HasHandleList = FALSE;
	CONSOLE_HANDLE_INFO ConsoleHandleInfo = { 0 };
	PS_MITIGATION_OPTIONS_MAP MitigationOptions = { 0 };
	PS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptions = { 0 };
	WIN32K_SYSCALL_FILTER Win32kFilter = { 0 };
	ULONG ComponentFilter = 0;
	MAXVERSIONTESTED_INFO MaxVersionTested = { 0 };
	PS_BNO_ISOLATION_PARAMETERS BnoIsolation = { 0 };
	DWORD DesktopAppPolicy = 0;
	ISOLATION_MANIFEST_PROPERTIES IsolationManifest = { 0 };
	UNICODE_STRING PackageFullNameReserved = { 0 };
	BOOLEAN ConsoleReference = FALSE;
	BOOL IsRestricted = FALSE;
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

	DWORD AppModelPolicyValue = 0;
	ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo = 0;
	PS_PKG_CLAIM PackageClaims = { 0 };
	ULONG_PTR AttributesPresent = 0;
	BOOL AppXPackageBreakaway = 0;
	BOOL BypassAppxExtension = 0;
	BOOL AccessDenied = FALSE;
	UNICODE_STRING SubSysCommandLine = { 0 };

	ULONG AppResumeRequired = 0;
	DWORD UnknowActivationSxsFlags = 0;
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
	ULONG DataLength = 0;
	SubSysCommandLine.Buffer = NULL;

	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	LPWSTR AppXCommandline = 0;

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
		return STATUS_INVALID_PARAMETER;//VDM
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return FALSE;
	}
	else if (!(dwCreationFlags & CREATE_SHARED_WOW_VDM) && *(BOOLEAN*)((char*)BaseStaticServerData + 0x7F4))//BASE_STATIC_SERVER_DATA->DefaultSeparateVDM
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
	if (dwCreationFlags & CREATE_SECURE_PROCESS)// CREATE_SECURE_PROCESS
	{
		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_SECURE_PROCESS;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(ULONGLONG); //为什么是8而不是24?? ??????????????????????
		AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
		AttributeList.Attributes[AttributeListCount].ValuePtr = &TrustletCreateAttributes;//  in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
	}
	lpProcessInformation->hProcess = NULL;
	lpProcessInformation->hThread = NULL;
	if (lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		Status = RtlCreateEnvironmentEx(lpEnvironment, (PVOID*)&UnicodeEnvironment, RTL_CREATE_ENVIRONMENT_TRANSLATE);
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
	
	ExtendStartupInfo.StartupInfo = *lpStartupInfo;

	if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT)
	{
		if (ExtendStartupInfo.StartupInfo.cb != 0x70)
		{
			BaseSetLastNTError(STATUS_INVALID_PARAMETER);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		lpAttributeList = ExtendStartupInfo.lpAttributeList;
		if (lpAttributeList)
		{
			/*
				win 10 20H1 23

				win 10 21H1 23

				win 10 21H2 25

				win 11 21H2 26
			*/
			Status = BasepConvertWin32AttributeList(
				lpAttributeList,
				FALSE,
				&ExtendedFlags,
				&PackageFullName,
				&SecurityCapabilities,
				&HasHandleList,
				&ParentProcessHandle,
				&ConsoleHandleInfo,			// CONSOLE_HANDLE_INFO   //IN ProcessParameters ?<- CONSOLE_IGNORE_CTRL_C = 0x1// ? = 0x2// ? = 0x4 ???
				&MitigationOptions,			// PS_MITIGATION_OPTIONS_MAP 
				&MitigationAuditOptions,	// PS_MITIGATION_AUDIT_OPTIONS_MAP
				&Win32kFilter,              // WIN32K_SYSCALL_FILTER
				&ComponentFilter,           // int // ULONG ComponentFilter
				&MaxVersionTested,          // MAXVERSIONTESTED_INFO ???
				&BnoIsolation,              // PS_BNO_ISOLATION_PARAMETERS
				&DesktopAppPolicy,			// DWORD (PROCESS_CREATION_DESKTOP_APP_*)
				&IsolationManifest,         // in ISOLATION_MANIFEST_PROPERTIES // rev (diversenok) // since 19H2+
				&PackageFullNameReserved,
				&TrustletCreateAttributes.Attributes[0],
				&AttributeList,
				&AttributeListCount,
				25);//ProcThreadAttributeMax
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			if (lpAttributeList->PresentFlags & (1 << ProcThreadAttributeConsoleReference))// ProcThreadAttributeConsoleReference 10 
			{
				ConsoleReference = TRUE;
				if (SecurityCapabilities)
				{
					BaseSetLastNTError(STATUS_INVALID_PARAMETER);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
			}
			//0x80000 ??
			if ((lpAttributeList->PresentFlags & 0x80000) != 0)//  XXX EXTENDED_STARTUPINFO_PRESENT?
				IsRestricted = TRUE;
			if (ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_FORCE_BREAKAWAY)
				ProcessFlags |= PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY;
		}
	}

	if (!(dwCreationFlags & CREATE_SEPARATE_WOW_VDM))
	{
		BOOL IsInJob = FALSE;
		if (IsProcessInJob(ParentProcessHandle ? ParentProcessHandle : NtCurrentProcess(), NULL, &IsInJob) && IsInJob)
			dwCreationFlags = (dwCreationFlags & (~CREATE_SHARED_WOW_VDM)) | CREATE_SEPARATE_WOW_VDM;
	}
	if ((ExtendStartupInfo.StartupInfo.dwFlags & STARTF_USESTDHANDLES) && ExtendStartupInfo.StartupInfo.dwFlags & (STARTF_USEHOTKEY | STARTF_HASSHELLDATA))
		ExtendStartupInfo.StartupInfo.dwFlags &= ~(STARTF_USESTDHANDLES);

	if (lpCurrentDirectory)
	{
		CurrentDirectoryHeap = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH - 2);
		if (!CurrentDirectoryHeap)
		{
			BaseSetLastNTError(STATUS_NO_MEMORY);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		FullPathNameLength = GetFullPathNameW(lpCurrentDirectory, MAX_PATH - 1, CurrentDirectoryHeap, &FilePart);
		if (FullPathNameLength >= MAX_PATH)
		{
			wprintf(L"[*] GetFullPathNameW Status = 0x%08x\n", Status);
			RtlSetLastWin32Error(ERROR_DIRECTORY);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (!FullPathNameLength)
		{
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	Status = BaseFormatObjectAttributes(
		&LocalProcessObjectAttribute,
		lpProcessAttributes,
		NULL,
		&ProcessObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		wprintf(L"[-] BaseFormatObjectAttributes Status = 0x%08x\n", Status);
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
		wprintf(L"[-] BaseFormatObjectAttributes Status = 0x%08x\n", Status);
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
		
		if (AppExecutionAliasInfo && AppExecutionAliasInfo->BreakawayModeLaunch != TRUE)
		{
			wprintf(L"[+] AppExecutionAliasInfo is exist and no Breakaway, we try to set with AppAliasTokenHandle!\n");
			AppXTokenHandle = AppExecutionAliasInfo->TokenHandle;
			TokenHandle = AppXTokenHandle;
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
			RtlDestroyEnvironment((PWSTR)AppXEnvironment);
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
		if (IsBasepProcessInvalidImagePresent())
		{

			BasepFreeAppCompatData(AppCompatData, AppCompatSxsData, AppCompatCacheData);
			AppCompatData = NULL;
			AppCompatDataSize = 0;
			AppCompatSxsData = NULL;
			AppCompatSxsDataSize = 0;
			AppCompatCacheData = NULL;
			AppCompatCacheDataSize = 0;
		}
		if (!VdmBinaryType && IsBasepProcessInvalidImagePresent())
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
				wprintf(L"[*] Lead Quote Detected , SearchRetry Disabled...\n");
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
				wprintf(L"[-] RtlGetExePath = 0x%08x\n", Status);
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
		if (PathType > RtlPathTypeRootLocalDevice || !BasepAdjustApplicationPath(&Win32ImagePath))//???????????
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
		if (NtCurrentPeb()->IsPackagedProcess && !AppExecutionAliasInfo)
		{
			AppModelPolicyValue = ImplicitPackageBreakaway_Denied;
			Status = AppModelPolicy_GetPolicy_Internal(
				NtCurrentThreadEffectiveToken(),//-6
				ImplicitPackageBreakaway_Internal,
				&AppModelPolicyValue,
				&PackageClaims,
				&AttributesPresent) | 0x10000000;
			wprintf(L"[*] AppModelPolicy_GetPolicy_Internal: 0x%08x\n", Status);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			if (AppModelPolicyValue == ImplicitPackageBreakaway_Allowed && PackageClaims.Flags == (PSM_ACTIVATION_TOKEN_FULL_TRUST | BREAKAWAY_INHIBITED))
				AppModelPolicyValue = ImplicitPackageBreakaway_DeniedByApp;

			if ((AppModelPolicyValue == ImplicitPackageBreakaway_Allowed && (DesktopAppPolicy & 6) == 0)// PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE | PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_DISABLE_PROCESS_TREE? 
				|| (AppModelPolicyValue == ImplicitPackageBreakaway_DeniedByApp && (DesktopAppPolicy & 5) == 1))
			{
				Status = STATUS_UNSUCCESSFUL;
				wprintf(L"IsCheckAppXPackageBreakawayPresent = 0x%p\n", IsCheckAppXPackageBreakawayPresent);
				if (IsCheckAppXPackageBreakawayPresent())
				{
					Status = CheckAppXPackageBreakaway(Win32ImagePath.Buffer, &AppXPackageBreakaway);
					if (!NT_SUCCESS(Status))
						AppXPackageBreakaway = FALSE;
				}
				else
				{
					return Status;
				}
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			AppModelPolicyValue = BypassCreateProcessAppxExtension_False;
			AttributesPresent = 0;
			Status = AppModelPolicy_GetPolicy_Internal(
				NtCurrentThreadEffectiveToken(),
				BypassCreateProcessAppxExtension,
				&AppModelPolicyValue,
				&PackageClaims,
				&AttributesPresent);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(STATUS_UNSUCCESSFUL);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			else if (AppModelPolicyValue == BypassCreateProcessAppxExtension_True)
			{
				BypassAppxExtension = TRUE;
			}
		};
		if (!AppXPackageBreakaway && (PackageFullName.Length || NtCurrentPeb()->IsPackagedProcess && !BypassAppxExtension))
		{
			//wprintf(L"[+] AppX RealCore!\n");
			//wprintf(L"[*] BasepAppXExtension_Address = 0x%p\n", BasepAppXExtension);
			if (!IsBasepProcessInvalidImagePresent())
			{
				Status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				//rcx - rdx - r8 - r9 - rest on stack
				Status = BasepAppXExtension(
					AppXTokenHandle,
					&PackageFullName,
					SecurityCapabilities,//NULL
					lpEnvironment,//NULL
					&AppXProcessContext,
					&AppXEnvironment); //AppXEnvironment = 0?
				wprintf(L"[*] BasepAppXExtension: 0x%08x\n", Status);
				//wprintf(L"[*] AppXProcessContext: 0x%p\n", AppXProcessContext);
				//wprintf(L"[*] AppXProcessContext->AppXFlags: 0x%d", AppXProcessContext->AppXFlags);
			}
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

				if (AppXProcessContext->AppXCurrentDirectory && !AppExecutionAliasInfo)
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
		//wprintf(L"[*] Present CurrentTokenHandle: 0x%p\n", CurrentTokenHandle);
		if (IsRestricted)// Isolation容器限制
		{
			if (SecurityCapabilities || NtCurrentPeb()->IsAppContainer)// IsAppContainer  AppContainer not support
			{
				BaseSetLastNTError(STATUS_NOT_SUPPORTED);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			//*RestrictedUserToken = TokenHandle;
			CurrentTokenHandle = TokenHandle;
		}
		else
		{
			CurrentTokenHandle = AppXTokenHandle;
		}
		//wprintf(L"[*] CurrentTokenHandle: 0x%p\n", CurrentTokenHandle);
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
			if (IsBasepProcessInvalidImagePresent())
				Status = BasepAppContainerEnvironmentExtension(SecurityCapabilities->AppContainerSid, lpEnvironment, &AppXEnvironmentExtension);
			else
				Status = STATUS_SUCCESS;
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
		if (IsRestricted)
		{
			// Win 11  
			// Status = BasepProcessBnoIsolationParameter(CurrentTokenHandle, &BnoIsolation)
			// if...
			if (BnoIsolation.Handles)
			{
				Status = STATUS_INVALID_PARAMETER;
			}
			else if (BnoIsolation.IsolationEnabled)
			{
				if (!BnoIsolation.IsolationPrefix.Buffer)
				{
					Status = STATUS_INVALID_PARAMETER;
				}
				Status = BasepCreateBnoIsolationObjectDirectories(CurrentTokenHandle, &BnoIsolation);
			}
			else
			{
				Status = STATUS_SUCCESS;
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

		if (AppXProcessContext && AppXProcessContext->s1.AppXProtectedProcessLight)
		{
			wprintf(L"[*] AppXProtectedProcessLight\n");
			AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_PROTECTION_LEVEL;// PsAttributeProtectionLevel
			AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_PROTECTION);
			AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
			AttributeList.Attributes[AttributeListCount].Value = (ULONG_PTR)0x81;
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
			if ((ExtendStartupInfo.StartupInfo.dwFlags & STARTF_USESTDHANDLES) == 0 && !ParentProcessHandle && (dwCreationFlags & (CREATE_NO_WINDOW | CREATE_NEW_CONSOLE | DETACHED_PROCESS)) == 0)// none of CREATE_NO_WINDOW CREATE_NEW_CONSOLE DETACHED_PROCESS
			{
				wprintf(L"[*] StdHandle Mode 1\n");
				StdHandle.StdHandleSubsystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
				StdHandle.Flags = StdHandle.Flags & -0x20 | PsRequestDuplicate;
				AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
				AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_STD_HANDLE_INFO);
				AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
				AttributeList.Attributes[AttributeListCount].ValuePtr = &StdHandle;
				AttributeListCount++;
			}
			if ((ExtendStartupInfo.StartupInfo.dwFlags & STARTF_USESTDHANDLES) && ParentProcessHandle)
			{
				wprintf(L"[*] StdHandle Mode 2\n");
				StdHandle.StdHandleSubsystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
				StdHandle.Flags = StdHandle.Flags & -0x20 | PsAlwaysDuplicate;
				AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
				AttributeList.Attributes[AttributeListCount].Size = sizeof(PS_STD_HANDLE_INFO);
				AttributeList.Attributes[AttributeListCount].ReturnLength = 0;
				AttributeList.Attributes[AttributeListCount].ValuePtr = &StdHandle;
				AttributeListCount++;
			}
		}
		if (!(dwCreationFlags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) || NtCurrentPeb()->ReadImageFileExecOptions)
		{
			if (QueryImageFileKeyFailPresent == TRUE)
			{
				QueryImageFileKeyFailPresent = FALSE;
				CreateInfo.InitState.u1.s1.IFEOSkipDebugger = TRUE;//0x04
			}
		}
		else
		{
			CreateInfo.InitState.u1.s1.IFEOSkipDebugger = CreateInfo.InitState.u1.s1.IFEODoNotPropagateKeyState = TRUE;//0x0c
		}
		CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
		CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = IMAGE_FILE_DLL;
		CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

		if (!ExtendStartupInfo.StartupInfo.lpDesktop)
			ExtendStartupInfo.StartupInfo.lpDesktop = NtCurrentPeb()->ProcessParameters->DesktopInfo.Buffer;

		if (!AppXProcessContext || !AppXProcessContext->PackageFullName || !(*AppXProcessContext->PackageFullName) || AppXProcessContext->s1.AppXManifestDetected) //AppXManifestDetect
		{
			//wprintf(L"[*] Enable DetectManifest\n");
			CreateInfo.InitState.u1.s1.DetectManifest = TRUE;//if ***, will not use DetectManifest 
		}

		RtlWow64GetProcessMachines(NtCurrentProcess(), &CurrentProcessMachine, &TargetProcessMachine);
		/*
		* 真看不懂 什么东西啊
		if (TargetProcessMachine != IMAGE_FILE_MACHINE_ARM64
			|| !IsBasepProcessInvalidImagePresent()
			|| (unsigned int)BasepQueryModuleChpeSettings(// Compiled Hybrid Portable Executable
				&ChpeModSetting,
				32i64,
				Win32PathName.Buffer,
				&Flags_Offset,
				lpEnvironment,
				&PackageFullName,
				&AppCompatCacheData,
				&AppCompatCacheDataSize,
				&AppCompatSxsData,
				&AppCompatSxsDataSize))
		{
			ChpeModSetting.ChpeUnknow1 = NULL;
			ChpeModSetting.ChpeFlags1 = 0x80000000;
			ChpeModSetting.ChpeUnknow2 = NULL;
			ChpeModSetting.ChpeFlags2 = NULL;
			ChpeModSetting.Reversed1 = NULL;
			ChpeModSetting.Reversed2 = 2;
			ChpeModSetting.Reversed3 = 84;
			ChpeModSetting.Reversed4 &= ~1u;
			ChpeModSetting.Unknow = 0i64;
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
			&ExtendStartupInfo.StartupInfo,
			dwCreationFlags,//10  [0]
			DefaultInheritOnly,//11 False DefaultInheritOnly 的作用是继承当前进程的std标准输入输出流->重定向
			ProcessFlags | (AppXPackageBreakaway ? INHERIT_PARENT_AFFINITY : 0), //12  ProcessFlags = 0x200
			&ConsoleHandleInfo, //13
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
		PackageClaims.Origin = (ULONG_PTR)ProcessParameters; //什么鬼?
		if (!ProcessParameters)
		{
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (AppXProcessContext && AppXProcessContext->s1.AppXGlobalizationOverride)
		{
			ProcessParameters->Flags |= 0x8000000;
		}
		if (AppExecutionAliasInfo && !lpCurrentDirectory)
		{
			DosPathLength = ProcessParameters->CurrentDirectory.DosPath.Length;
			PWSTR TempHeap = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, (SIZE_T)DosPathLength + 2);
			CurrentDirectoryHeap = TempHeap;
			if (!TempHeap)
			{
				BaseSetLastNTError(STATUS_NO_MEMORY);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			StringCbCopyW(TempHeap, DosPathLength + sizeof(WCHAR), ProcessParameters->CurrentDirectory.DosPath.Buffer);
			lpCurrentDirectory = TempHeap;
		}

		AttributeList.Attributes[AttributeListCount].Attribute = PS_ATTRIBUTE_CHPE;
		AttributeList.Attributes[AttributeListCount].Size = sizeof(BOOLEAN);
		AttributeList.Attributes[AttributeListCount].ReturnLength = NULL;
		//AttributeList.Attributes[AttributeListCount].ValuePtr = QueryChpeConfiguration(&NtImageName, (ChpeModSetting.Reversed3 >> 6) & 1);
		ChpeOption = TRUE;
		AttributeList.Attributes[AttributeListCount].Value = ChpeOption;
		AttributeListCount++;

		AttributeList.Attributes[0].Size = NtImagePath.Length;
		AttributeList.Attributes[0].ValuePtr = NtImagePath.Buffer;
		AttributeList.TotalLength = AttributeListCount * sizeof(PS_ATTRIBUTE) + sizeof(SIZE_T);

		if (AppExecutionAliasInfo && AppExecutionAliasInfo->BreakawayModeLaunch != TRUE)
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
			if (!ImpersonateLoggedOnUser(AppExecutionAliasInfo->TokenHandle))
			{
				if (SaveImpersonateTokenHandle)
					NtClose(SaveImpersonateTokenHandle);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			ThreadTokenImpersonated = TRUE;
			ProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)PackageClaims.Origin; //???????
			CurrentTokenHandle = TokenHandle;
		}
		//wprintf(L"[*] dwCreationFlags: 0x%08x\n", dwCreationFlags);
		//wprintf(L"[*] ProcessFlags: 0x%08x\n", ProcessFlags);
		//wprintf(L"[*] AttributeList.TotalLength: %lld\n", AttributeList.TotalLength);
		wprintf(L"[*] InitFlags 0x%08lx\n", CreateInfo.InitState.u1.InitFlags);
		wprintf(L"[*] AttributeListCount: %d\n", AttributeListCount);


		Status = NtCreateUserProcess(&ProcessHandle, &ThreadHandle, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, &AttributeList);
	
		if (ThreadTokenImpersonated)
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
			//CreateInfoOutPut(CreateInfo);
			//SectionImageInfomationOutPut(SectionImageInfomation);
			
			wprintf(L"[+] NtCreateUserProcess Success! PID=%lld, TID=%lld\n", (ULONGLONG)ClientId.UniqueProcess, (ULONGLONG)ClientId.UniqueThread);
			wprintf(L"[+] OutputFlags: 0x%08x\n", CreateInfo.SuccessState.u2.OutputFlags);//0x08 // 0x0a = 0x08 | 0x02
			break;
		}
		ProcessHandle = NULL;
		ThreadHandle = NULL;
		wprintf(L"[-] NtCreateUserProcess Fail: 0x%08x, CreateInfo.State = %d\n", Status, CreateInfo.State);
		//wprintf(L"[-] OutputFlags: 0x%08x\n", CreateInfo.SuccessState.u2.OutputFlags);
		switch (CreateInfo.State)
		{

		case PsCreateInitialState:
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
			break;
		case PsCreateFailOnFileOpen:// STATUS_IO_REPARSE_TAG_NOT_HANDLED -> AppX
			if (AppExecutionAliasInfo || Status != STATUS_IO_REPARSE_TAG_NOT_HANDLED && Status != STATUS_ACCESS_DENIED)
				goto AppAliasError;
			AliasStatus = STATUS_NOT_IMPLEMENTED;//win 11
			if (Status == STATUS_ACCESS_DENIED)
			{
				//Win 11 LoadAppExecutionAliasInfoForExecutable
				AccessDenied = TRUE;
				if (IsGetAppExecutionAliasPathPresent())
				{
					DWORD Heapsize = 0;
					AliasStatus = GetAppExecutionAliasPath(Win32ImagePath.Buffer, AppAliasTokenHandle, 0, &Heapsize);
					if (AliasStatus == 0x7A)//?
					{
						AppExecutionAliasPathHeap = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * Heapsize);
						AliasPathHeap = AppExecutionAliasPathHeap;
						AliasStatus = GetAppExecutionAliasPath(Win32ImagePath.Buffer, AppAliasTokenHandle, AppExecutionAliasPathHeap, &Heapsize);
						AliasStatus |= AliasStatus ? 0xC0070000 : 0;
					}
					else if (AliasStatus)
					{
						AliasStatus |= 0xC0070000;
					}
				}
				else
				{
					AppExecutionAliasPathHeap = Win32ImagePath.Buffer;
				}

			}
			else if (IsLoadAppExecutionAliasInfoExPresent())
			{
				AccessDenied = FALSE;
				AppExecutionAliasPathHeap = Win32ImagePath.Buffer;
				AliasStatus = STATUS_SUCCESS;//compatibility
			}

			if (NT_SUCCESS(AliasStatus))
			{
				AliasStatus = LoadAppExecutionAliasInfoEx(AppExecutionAliasPathHeap, TokenHandle, &AppExecutionAliasInfo);//Alias Core 关键核心
				wprintf(L"[*] LoadAppExecutionAliasInfoEx: 0x%08x\n", AliasStatus);
			}
			//wprintf(L"[*] ValidateAppXAliasFallback Address: 0x%p\n", ValidateAppXAliasFallback);
			if (AccessDenied && NT_SUCCESS(AliasStatus) && AppExecutionAliasInfo)
			{
				wprintf(L"[-] AppXAliasFallback, Let's validate it\n");
				AliasStatus = ValidateAppXAliasFallback(Win32ImagePath.Buffer, AppExecutionAliasInfo);
			}
			
			if (!NT_SUCCESS(AliasStatus) || !AppExecutionAliasInfo)//...
			{
				if (AliasStatus == 0xC0073D00)
					Status = 0xC0073D00;
			AppAliasError:
				if (!RtlIsDosDeviceName_U(lpApplicationName))
				{
					BaseSetLastNTError(Status);
				}
				else
				{
					RtlSetLastWin32Error(ERROR_BAD_DEVICE);
				}
				bStatus = FALSE;
				goto Leave_Cleanup;
			}

			lpApplicationName = AppExecutionAliasInfo->AppAliasBaseImagePath;
			TokenHandle = AppExecutionAliasInfo->TokenHandle;

			//Win 11 BuildAppExecutionAliasCommandLine
			if (AppExecutionAliasInfo->BreakawayModeLaunch == TRUE)
			{
				wprintf(L"[*] AppXCommandline Breakaway 1\n"); //SystemUWPLauncher.exe
				SIZE_T Length = sizeof(WCHAR) * (wcslen(AppExecutionAliasInfo->BreakawayCommandeLine) + wcslen(lpCommandLine) + 2);
				AppXCommandline = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), 0, Length);
				if (AppXCommandline)
				{
					StringCbCopyW(AppXCommandline, Length, AppExecutionAliasInfo->BreakawayCommandeLine);
					StringCbCatW(AppXCommandline, Length, L" ");
					StringCbCatW(AppXCommandline, Length, lpCommandLine);
				}
			}
			else
			{
				wprintf(L"[*] AppXCommandline Normal 2\n");
				RtlInitUnicodeString(&PackageFullName, AppExecutionAliasInfo->AppXPackageName);//Win 11 Keep
				AppXPackageBreakaway = FALSE;
				SIZE_T Length = sizeof(WCHAR) * wcslen(lpCommandLine) + 2;
				AppXCommandline = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, Length);
				if (AppXCommandline)
				{
					StringCbCopyExW(AppXCommandline, Length, lpCommandLine, 0, 0, 0);
					
				}
				wprintf(L"[+] PackageFullName: %ls\n", PackageFullName.Buffer);
			}
			lpCommandLine = AppXCommandline;
			// wprintf(L"[+] Struct AppExecutionAliasInfo Located in: 0x%p\n", AppExecutionAliasInfo);
			//wprintf(L"[*] AppExecutionAlias Name: %ls\n", lpApplicationName);
			//wprintf(L"[*] Final TokenHandle: 0x%08llx\n", TokenHandle);
			//wprintf(L"[+] Final lpCommandLine for AppX: %ls\n", lpCommandLine);
			break;
		case PsCreateFailOnSectionCreate:
			FileHandle = CreateInfo.FailSection.FileHandle;

			ntvdm64 = LoadLibraryW(L"ntvdm64.dll");
			NtVdm64CreateProcessInternalW = (NtVdm64CreateProcessInternalW_)GetProcAddress(ntvdm64, "NtVdm64CreateProcessInternalW");
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
					NewCommandLine = (LPWSTR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, *KernelBaseGetGlobalData(), 2 * MAX_PATH + 6);
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
						if (GetEnvironmentVariableW(L"SystemRoot", NewCommandLine, MAX_PATH - 17) > MAX_PATH - 18) //   wcslen("\\system32\\cmd.exe")
						{
							BaseSetLastNTError(STATUS_NOT_A_DIRECTORY);
							bStatus = FALSE;
							goto Leave_Cleanup;
						}
						StringCbCatW(NewCommandLine, MAX_PATH, L"\\system32\\cmd.exe");// RtlStringCchCatW ?= StringCbCatW
					}
					StringCbCatW(NewCommandLine, MAX_PATH + 3, L" /c");// RtlStringCchCatW ?= StringCbCatW
					//SearchRetry = 1 ???
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
					if (IsBasepProcessInvalidImagePresent() && BaseIsDosApplication(&NtImagePath))
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
					SaferStatus = IsBasepProcessInvalidImagePresent() ?
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
			}
			if (Status == STATUS_INVALID_IMAGE_WIN_16)
			{
				if (IsBasepProcessInvalidImagePresent())
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
						&ExtendStartupInfo.StartupInfo,
						lpProcessInformation,
						NULL);
					wprintf(L"[*] NtVdm64CreateProcessInternalW bStatus = %d\n", bStatus);
				}
				else
					bStatus = FALSE;
				if (!bStatus && NtCurrentTeb()->LastErrorValue == ERROR_EXE_MACHINE_TYPE_MISMATCH && IsBasepProcessInvalidImagePresent())
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
						&ExtendStartupInfo.StartupInfo,
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
				ImageFileDebuggerCommand = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(WCHAR) * MAX_PATH + 2);
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
				*(ImageFileDebuggerCommand + sizeof(WCHAR) * MAX_PATH) = NULL;
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
				
				wprintf(L"[!] Try to Redirect Unpackaged Executable via OSBuildNumber >= 21313\n");
				/* https://docs.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-extensions */
				AppAliasRedirect = FALSE;
				Status = LdrQueryImageFileKeyOption(IFEOKey, L"AppExecutionAliasRedirect", REG_DWORD, (LPCWSTR)&AppAliasRedirect, sizeof(BOOL), NULL);
				if (NT_SUCCESS(Status) && AppAliasRedirect == TRUE)
				{
					Status = LoadAppExecutionAliasInfoForExecutable(Win32ImagePath.Buffer, CurrentTokenHandle, RtlProcessHeap(), &AppExecutionAliasInfo);
					ExtendedAppExecutionAliasInfo_New* AppExecutionAliasInfoNew = (ExtendedAppExecutionAliasInfo_New*)AppExecutionAliasInfo;//QAQ
					if (NT_SUCCESS(Status) && AppExecutionAliasInfoNew)
					{
						Status = ValidateAppExecutionAliasRedirectPackageIdentity(IFEOKey, AppExecutionAliasInfoNew);
					}
					else if (Status == 0xC0073D00)
					{
						NtClose(IFEOKey);
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
					if (NT_SUCCESS(Status))
					{
						lpApplicationName = AppExecutionAliasInfo->AppAliasBaseImagePath;
						TokenHandle = AppExecutionAliasInfo->TokenHandle;
						if (AppExecutionAliasInfo->BreakawayModeLaunch == TRUE)
						{
							wprintf(L"[*] AppXCommandline Breakaway 1\n"); //SystemUWPLauncher.exe
							SIZE_T Length = sizeof(WCHAR) * (wcslen(AppExecutionAliasInfo->BreakawayCommandeLine) + wcslen(lpCommandLine) + 2);
							AppXCommandline = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), 0, Length);
							if (AppXCommandline)
							{
								StringCbCopyW(AppXCommandline, Length, AppExecutionAliasInfo->BreakawayCommandeLine);
								StringCbCatW(AppXCommandline, Length, L" ");
								StringCbCatW(AppXCommandline, Length, lpCommandLine);
							}
						}
						else
						{
							wprintf(L"[*] AppXCommandline Normal 2\n");
							RtlInitUnicodeString(&PackageFullName, AppExecutionAliasInfo->AppXPackageName);//Win 11 Keep
							AppXPackageBreakaway = FALSE;
							SIZE_T Length = sizeof(WCHAR) * wcslen(lpCommandLine) + 2;
							AppXCommandline = (LPWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, Length);
							if (AppXCommandline)
							{
								StringCbCopyExW(AppXCommandline, Length, lpCommandLine, 0, 0, 0);
							}
							wprintf(L"[+] PackageFullName: %ls\n", PackageFullName.Buffer);
						}
						if (AppXCommandline)
							lpCommandLine = AppXCommandline;
					}	
				}	
			}
			if (OSBuildNumber >= 21313)
				NtClose(IFEOKey);
			QueryImageFileKeyFailPresent = TRUE;
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
	if (SectionImageInfomation.SubSystemType > IMAGE_SUBSYSTEM_WINDOWS_CUI)
	{
		RtlSetLastWin32Error(ERROR_CHILD_NOT_COMPLETE);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	if (SectionImageInfomation.SubSystemMajorVersion >= 3 || (SectionImageInfomation.SubSystemMajorVersion != 3 || SectionImageInfomation.SubSystemMinorVersion >= 10))
	{
		if (SectionImageInfomation.SubSystemMajorVersion <= SharedUserData->NtMajorVersion
			&& (SectionImageInfomation.SubSystemMajorVersion != SharedUserData->NtMajorVersion || SectionImageInfomation.SubSystemMinorVersion <= SharedUserData->NtMinorVersion))
		{
			//wprintf(L"[+] ImageVersion OK!\n");
			ImageVersionOk = TRUE;
		}
		else
		{
			RtlSetLastWin32Error(ERROR_BAD_EXE_FORMAT);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	else
	{
		ImageVersionOk = FALSE;
	}
	if (!ImageVersionOk)
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

	Status = IsBasepProcessInvalidImagePresent() ? BasepCheckWebBladeHashes(FileHandle) : STATUS_SUCCESS;

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
	if (IsBasepProcessInvalidImagePresent())
		Status = BasepIsProcessAllowed((LPWSTR)lpApplicationName);
	else
		Status = STATUS_SUCCESS;
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
		bStatus = IsBasepProcessInvalidImagePresent() ? BaseUpdateVDMEntry(UPDATE_VDM_PROCESS_HANDLE, &VdmWaitHandle, VdmTaskId, VdmBinaryType) : NULL;
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
		Status = IsBasepProcessInvalidImagePresent()
			? BasepCheckWinSaferRestrictions(CurrentTokenHandle, lpApplicationName, FileHandle, &PackageFullName)
			: NULL;
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
			//If this is a .NET ILONLY that needs to run in a 64-bit addressspace, then let SXS be aware of this
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
		else if (Protection.Level == 0x81)
		{
			//Type = PsProtectedTypeProtectedLight | Signer = PsProtectedSignerApp
			AppXProtectEnabled = TRUE;
		}
	}

	AppCompatImageMachine = 0;
	if ((!CreateInfo.SuccessState.u2.s2.ProtectedProcess || AppXProtectEnabled) && IsBasepProcessInvalidImagePresent())
	{
		// CompatCacheLookupAndWriteToProcess->NtApphelpCacheControl
		BasepQueryAppCompat(
			&SectionImageInfomation,
			CreateInfo.SuccessState.u2.s2.AddressSpaceOverride,
			ImageProcessorArchitecture,
			FileHandle,
			ProcessHandle,
			Win32ImagePath.Buffer,
			lpEnvironment,
			&PackageFullName,
			&AppCompatCacheData,
			&AppCompatCacheDataSize,
			&AppCompatSxsData,
			&AppCompatSxsDataSize,
			&AppCompatSxsSafeMode,		//13
			&AppCompatPrivilegeFlags,   //14 0x4 == RunAsAdmin 0x0000000400000000 -> CompatMode old than Vista (NT6)
			&UnknowCompatCache3,		//15
			&AppCompatImageMachine,
			&MaxVersionTested,			//PackageOnly
			&DeviceFamilyID				//PackageOnly DEVICEFAMILYINFOENUM_DESKTOP = 3
		);
		wprintf(L"[*] AppCompatCacheData = 0x%p, AppCompatCacheDataSize = %ld\n", AppCompatCacheData, AppCompatCacheDataSize);
		wprintf(L"[*] AppCompatSxsData = 0x%p, AppCompatSxsDataSize = %ld\n", AppCompatSxsData, AppCompatSxsDataSize);
		//MaxVersionTested = 0x000A000047BA0000
		wprintf(L"[*] AppCompatSxsSafeMode = %d\n", AppCompatSxsSafeMode);
		wprintf(L"[*] AppCompatPrivilegeFlags = 0x%08llx\n", AppCompatPrivilegeFlags); //0x4
		wprintf(L"[*] UnknowCompatCache3 = 0x%08x\n", UnknowCompatCache3);
		wprintf(L"[*] AppCompatImageMachine = 0x%04x\n", AppCompatImageMachine);//IMAGE_FILE_MACHINE_AMD64
		wprintf(L"[*] DeviceFamilyID = %d\n", DeviceFamilyID);//DEVICEFAMILYINFOENUM_DESKTOP
	}
	if (!CreateInfo.SuccessState.u2.s2.ProtectedProcess || CreateInfo.SuccessState.u2.s2.ProtectedProcessLight)
	{
		BaseCreateProcessMessage->Sxs.ProcessParameterFlags = CreateInfo.SuccessState.CurrentParameterFlags;
		if (IsBasepProcessInvalidImagePresent())
		{
			//wprintf(L"[+] OS: %d\n", OSBuildNumber);
			//wprintf(L"[*] Windows 10 2004+ | Windows Server 2022\n");;
			Status = BasepConstructSxsCreateProcessMessage(
				&NtImagePath,
				&Win32ImagePath,
				FileHandle,
				ProcessHandle,
				SectionHandle,
				CurrentTokenHandle,
				CreateInfo.SuccessState.u2.s2.DevOverrideEnabled,//0x04
				AppCompatSxsSafeMode,
				AppCompatSxsData,
				AppCompatSxsDataSize,
				(SectionImageInfomation.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,
				(AppXProcessContext && !AppXProcessContext->s1.AppXManifestDetected) ? AppXProcessContext->AppXCurrentDirectory : NULL,
				PebAddressNative,
				ManifestAddress,
				ManifestSize,
				&CreateInfo.SuccessState.CurrentParameterFlags,
				&BaseCreateProcessMessage->Sxs,
				&SxsCreateProcessUtilityStruct
			);

			if (!NT_SUCCESS(Status))
			{
				wprintf(L"[-] BasepConstructSxsCreateProcessMessage: 0x%08x\n", Status);
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

	if (SectionImageInfomation.SubSystemType == IMAGE_SUBSYSTEM_WINDOWS_GUI || IsWowBinary)
	{
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT);
		CurrentImageHeaders = RtlImageNtHeader(GetModuleHandleA(NULL));
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
	if (StartInfo.dwFlags & STARTF_FORCEONFEEDBACK)
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle | BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);
	if (StartInfo.dwFlags < 0)
		BaseCreateProcessMessage->ProcessHandle = (HANDLE)((ULONG_PTR)BaseCreateProcessMessage->ProcessHandle & ~BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON);
	if ((StartInfo.dwFlags & 0x10000) != 0)
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
			CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
			CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;
			CaptureStringsCount = 4;
		}
		else
		{
			CsrStringsToCapture[0] = &BaseCreateProcessMessage->Sxs.Manifest.Path;
			CsrStringsToCapture[1] = &BaseCreateProcessMessage->Sxs.Policy.Path;
			CsrStringsToCapture[2] = &BaseCreateProcessMessage->Sxs.AssemblyDirectory;
			CsrStringsToCapture[3] = &BaseCreateProcessMessage->Sxs.CacheSxsLanguageBuffer;
			CsrStringsToCapture[4] = &BaseCreateProcessMessage->Sxs.AssemblyIdentity;
			CaptureStringsCount = 5;
		}
		Status = CsrCaptureMessageMultiUnicodeStringsInPlace(&CaptureBuffer, CaptureStringsCount, CsrStringsToCapture);
		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] CsrCaptureMessageMultiUnicodeStringsInPlace: 0x%08x\n", Status);
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}

	//BaseCreateProcessMessageOutPut(BaseCreateProcessMessage->Sxs);
	CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage, CaptureBuffer, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess2), sizeof(BASE_CREATEPROCESS_MSG));
	if (!NT_SUCCESS((NTSTATUS)ApiMessage.Status))
	{
		wprintf(L"[-] CsrClientCallServer: 0x%08x\n", ApiMessage.Status);
		BaseSetLastNTError(ApiMessage.Status);
		bStatus = FALSE;
		goto Leave_Cleanup;
	}
	wprintf(L"------------------------------------------------------------------\n");
	//wprintf(L"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	BaseCreateProcessMessageOutPut(BaseCreateProcessMessage->Sxs);

	if (!CreateInfo.SuccessState.u2.s2.ProtectedProcess)
	{
		if (BaseCreateProcessMessage->Sxs.ProcessParameterFlags != CreateInfo.SuccessState.CurrentParameterFlags)
		{
			Status = BasepUpdateProcessParametersField(
				ProcessHandle,
				&BaseCreateProcessMessage->Sxs.ProcessParameterFlags,
				4,
				NULL,
				8,
				8,
				&CreateInfo);
			if (!NT_SUCCESS(Status))
			{
				wprintf(L"[-] BasepUpdateProcessParametersField: 0x%08x\n", Status);
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			wprintf(L"[*] BasepUpdateProcessParametersField: 0x%08x, Remote ProcessParameterFlags: 0x%08lx\n", Status, BaseCreateProcessMessage->Sxs.ProcessParameterFlags);
		}
	}
	if (!IsBatchFile && !(ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_FORCELUA) && !SecurityCapabilities)
	{
		ElevationFlags |= ELEVATION_FLAG_TOKEN_CHECKS;
		if (IsBasepProcessInvalidImagePresent())
		{
			Status = BaseCheckElevation(
				ProcessHandle,
				FileHandle,
				Win32ImagePath.Buffer,
				&ElevationFlags,
				AppCompatPrivilegeFlags,
				&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
				&BaseCreateProcessMessage->Sxs.AssemblyIdentity,
				UnknowCompatCache3, //a8 0x1 while?
				CurrentTokenHandle,
				NULL,
				NULL);
		}
		else
		{
			Status = STATUS_SUCCESS;
		}
		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] Elevation Check Error: 0x%08x\n", Status);
			if (Status == STATUS_ELEVATION_REQUIRED && !(ExtendedFlags & EXTENDED_PROCESS_CREATION_FLAG_ELEVATION_HANDLED) && IsBasepProcessInvalidImagePresent())
			{
				wprintf(L"[-] Process Elevation Required, ExtendedFlags = 0x%lx\n", ExtendedFlags);
				BaseWriteErrorElevationRequiredEvent();
			}
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	wprintf(L"[*] ElevationFlags = 0x%08x\n", ElevationFlags);

	if (*BaseCreateProcessMessage->Sxs.ApplicationUserModelId && !ConsoleReference && !AppExecutionAliasInfo && !ActivationToken)
	{
		wprintf(L"[+] Package Activation!\n");
		Win32Error = BasepGetPackageActivationTokenForSxS(
			BaseCreateProcessMessage->Sxs.ApplicationUserModelId,
			TokenHandle,
			&ActivationToken
		);
		if (Win32Error != 0)
		{
			RtlSetLastWin32Error(Win32Error);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
		if (ActivationToken)
		{
			UINT32 packageFullNameLength = 128;
			Win32Error = GetPackageFullNameFromToken(
				ActivationToken,
				&packageFullNameLength,
				packageFullName);
			if (Win32Error != 0)
			{
				RtlSetLastWin32Error(Win32Error);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
			RtlInitUnicodeString(&PackageFullName, packageFullName);
			goto RetryNtCreateUserProcess;
		}
	}
	if (IsBasepProcessInvalidImagePresent())
	{
		if (CreateInfo.SuccessState.u2.s2.ProtectedProcess && AppXProtectEnabled)
		{
			wprintf(L"[*] SafeMode AppCompatData Write.\n");
			BasepGetAppCompatData(
				Win32ImagePath.Buffer,
				PackageFullName.Buffer,
				&ElevationFlags,
				&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
				&BaseCreateProcessMessage->Sxs.SxsProcessorArchitecture,
				&BaseCreateProcessMessage->Sxs.SxsMaxVersionTested,
				&SectionImageInfomation,
				AppCompatImageMachine,
				MaxVersionTested.MaxVersionTested,
				DeviceFamilyID,
				&AppCompatCacheData,
				&AppCompatCacheDataSize,
				&AppCompatData,
				&AppCompatDataSize);
			if (!BasepInitAppCompatData(ProcessHandle, AppCompatData, AppCompatDataSize))
			{
				BaseSetLastNTError(STATUS_ACCESS_DENIED);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		else
		{
			wprintf(L"[*] Normal AppCompatData Write.\n");
			BasepGetAppCompatData(
				Win32ImagePath.Buffer,
				PackageFullName.Buffer,
				&ElevationFlags,//a3
				&BaseCreateProcessMessage->Sxs.ActivationContextRunLevel,
				&BaseCreateProcessMessage->Sxs.SxsProcessorArchitecture,// UNCORRECTED...
				&BaseCreateProcessMessage->Sxs.SxsMaxVersionTested,
				&SectionImageInfomation,
				AppCompatImageMachine,
				MaxVersionTested.MaxVersionTested,
				DeviceFamilyID,
				&AppCompatCacheData,
				&AppCompatCacheDataSize,
				&AppCompatData,
				&AppCompatDataSize);

			if (AppCompatData)
			{
				wprintf(L"[*] Prepare to write RemoteProcess ShimData via UserMode: 0x%p\n", AppCompatData);
				PVOID pAppCompatDataInNewProcess = 0;
				RegionSize = AppCompatDataSize;
				Status = NtAllocateVirtualMemory(ProcessHandle, &pAppCompatDataInNewProcess, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
				if (!NT_SUCCESS(Status)) {
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
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}

				Status = NtWriteVirtualMemory(
					ProcessHandle,
					&PebAddressNative->pShimData,
					&pAppCompatDataInNewProcess,
					8,
					NULL);
				if (!NT_SUCCESS(Status)) {
					BaseSetLastNTError(Status);
					bStatus = FALSE;
					goto Leave_Cleanup;
				}
				if (CreateInfo.SuccessState.PebAddressWow64)
				{
					//ULONG Buffer = pAppCompatDataInNewProcess;
					Status = NtWriteVirtualMemory(
						ProcessHandle,
						(PVOID)(CreateInfo.SuccessState.PebAddressWow64 + FIELD_OFFSET(PEB32, pShimData)),//((PPEB32)(CreateInfo.SuccessState.PebAddressWow64))->pShimData
						&pAppCompatDataInNewProcess,
						4,
						NULL);
					if (!NT_SUCCESS(Status)) {
						BaseSetLastNTError(Status);
						bStatus = FALSE;
						goto Leave_Cleanup;
					}
				}
			}
		}
	}

	if (!IsBatchFile && !CreateInfo.SuccessState.u2.s2.ProtectedProcess)
	{
		Status = IsBasepProcessInvalidImagePresent() ? BaseElevationPostProcessing(ElevationFlags, ImageProcessorArchitecture, ProcessHandle) : STATUS_SUCCESS;
		if (!NT_SUCCESS(Status))
		{
			BaseSetLastNTError(Status);
			bStatus = FALSE;
			goto Leave_Cleanup;
		}
	}
	if (AppXProcessContext)
	{
		Status = BasepPostSuccessAppXExtension(ProcessHandle, AppXProcessContext);
		wprintf(L"[*] BasepPostSuccessAppXExtension: 0x%08x\n", Status);
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
				0x400, //FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, PackageDependencyData);
				0x298,
				&CreateInfo);
			wprintf(L"[*] BasepUpdateProcessParametersField: 0x%08x, Remote PackageDependencyData: 0x%p\n", Status, AppXProcessContext->RemoteBaseAddress);
			if (!NT_SUCCESS(Status))
			{
				BaseSetLastNTError(Status);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		AppResumeRequired = 0;
		if (AppExecutionAliasInfo && (AppExecutionAliasInfo->BreakawayModeLaunch != TRUE))
		{
			BOOL NormalCompleteAppExecutionAliasProcessCreation = TRUE;
			Status = CompleteAppExecutionAliasProcessCreationEx(
				ProcessHandle,
				ThreadHandle,
				AppExecutionAliasInfo->BreakawayModeLaunch,
				lpCurrentDirectory,
				lpCommandLine,
				CurrentTokenHandle,
				&AppResumeRequired);
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
				&AppResumeRequired);
			if (Win32Error != 0)
			{
				RtlSetLastWin32Error(STATUS_UNSUCCESSFUL);
				bStatus = FALSE;
				goto Leave_Cleanup;
			}
		}
		if (AppResumeRequired & 1)
			dwCreationFlags |= CREATE_SUSPENDED;
	}
ThreadResumePre:
	if ((dwCreationFlags & CREATE_SUSPENDED) == 0)
	{
		Status = NtResumeThread(ThreadHandle, NULL);
		if (!NT_SUCCESS(Status))
		{
			wprintf(L"[-] NtResumeThread: 0x%08x\n", Status);
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
		if (VdmBinaryType == BINARY_TYPE_WIN16)
		{
			lpProcessInformation->hProcess = (HANDLE)((ULONG_PTR)VdmWaitHandle | 2);
			if (VdmCreationState & VDM_BEING_REUSED)
				ClientId = { 0 };
		}
		else
		{
			lpProcessInformation->hProcess = (HANDLE)((ULONG_PTR)VdmWaitHandle | 1);
		}
		if (ProcessHandle)
			NtClose(ProcessHandle);
	}
	else
	{
		lpProcessInformation->hProcess = ProcessHandle;
	}
	lpProcessInformation->hThread = ThreadHandle;
	lpProcessInformation->dwProcessId = (DWORD)ClientId.UniqueProcess;
	lpProcessInformation->dwThreadId = (DWORD)ClientId.UniqueThread;
	ProcessHandle = NULL;
	ThreadHandle = NULL;
Leave_Cleanup:
	LastErrorValue = NtCurrentTeb()->LastErrorValue;

	if (ImageFileDebuggerCommand)
		RtlFreeHeap(RtlProcessHeap(), 0, ImageFileDebuggerCommand);

	if (ExePathFullBuffer)
		RtlFreeHeap(RtlProcessHeap(), 0, ExePathFullBuffer);
	RtlFreeUnicodeString(&NtImagePath);
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
		RtlDestroyEnvironment((PWSTR)AppXEnvironment);
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
	}
	if (ProcessHandle)
		NtClose(ProcessHandle);
	if (IsBasepProcessInvalidImagePresent())
		BasepFreeAppCompatData(AppCompatData, AppCompatSxsData, AppCompatCacheData);
	RtlFreeUnicodeString(&SubSysCommandLine);
	if ((AnsiStringVDMEnv.Buffer || UnicodeStringVDMEnv.Buffer) && IsBasepProcessInvalidImagePresent())
		BaseDestroyVDMEnvironment(&AnsiStringVDMEnv, &UnicodeStringVDMEnv);
	if (VdmCreationState && !(VdmCreationState & VDM_CREATION_SUCCESSFUL))
	{
		if (IsBasepProcessInvalidImagePresent())
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
	if (AppXCommandline)
		RtlFreeHeap(RtlProcessHeap(), 0, AppXCommandline);
	if (AliasPathHeap)
		RtlFreeHeap(RtlProcessHeap(), 0, AliasPathHeap);
	BasepFreeBnoIsolationParameter(&BnoIsolation);
	NtCurrentTeb()->LastErrorValue = LastErrorValue;
	wprintf(L"[*] Clean up done.\n");
	return bStatus;
}