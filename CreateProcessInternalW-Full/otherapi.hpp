#define UMDF_USING_NTSTATUS
#include <ntstatus.h>
#include "structs.hpp"
#include "csrss.hpp"

//#define DEBUG_PRINT

#ifdef DEBUG_PRINT

#define dprintf(...) wprintf(__VA_ARGS__)

#else

#define dprintf(...) do{}while(0);

#endif // DEBUG_PRINT

#define HandleToULong( h ) ((ULONG)(ULONG_PTR)(h) )
#define HandleToLong( h )  ((LONG)(LONG_PTR) (h) )
#define ULongToHandle( ul ) ((HANDLE)(ULONG_PTR) (ul) )
#define LongToHandle( h )   ((HANDLE)(LONG_PTR) (h) )
#define PtrToUlong( p ) ((ULONG)(ULONG_PTR) (p) )
#define PtrToLong( p )  ((LONG)(LONG_PTR) (p) )
#define PtrToUint( p ) ((UINT)(UINT_PTR) (p) )
#define PtrToInt( p )  ((INT)(INT_PTR) (p) )
#define PtrToUshort( p ) ((unsigned short)(ULONG_PTR)(p) )
#define PtrToShort( p )  ((short)(LONG_PTR)(p) )
#define IntToPtr( i )    ((VOID *)(INT_PTR)((int)i))
#define UIntToPtr( ui )  ((VOID *)(UINT_PTR)((unsigned int)ui))
#define LongToPtr( l )   ((VOID *)(LONG_PTR)((long)l))
#define ULongToPtr( ul ) ((VOID *)(ULONG_PTR)((unsigned long)ul))

#define ULongToPeb32Ptr( ul ) ((PPEB32)(ULONG_PTR)((unsigned long)ul))
#define BasepQueryAppCompatString L"BasepQueryAppCompat"
#define BasepGetAppCompatDataString L"BasepGetAppCompatData"

#define szOID_KP_KERNEL_MODE_CODE_SIGNING "1.3.6.1.4.1.311.61.1.1"
#define szOID_KP_KERNEL_MODE_TRUSTED_BOOT_SIGNING "1.3.6.1.4.1.311.61.4.1"
#define szOID_REVOKED_LIST_SIGNER "1.3.6.1.4.1.311.10.3.19"
#define szOID_WINDOWS_KITS_SIGNER "1.3.6.1.4.1.311.10.3.20"
#define szOID_WINDOWS_RT_SIGNER "1.3.6.1.4.1.311.10.3.21"
#define szOID_PROTECTED_PROCESS_LIGHT_SIGNER "1.3.6.1.4.1.311.10.3.22"
#define szOID_WINDOWS_TCB_SIGNER "1.3.6.1.4.1.311.10.3.23"
#define szOID_PROTECTED_PROCESS_SIGNER "1.3.6.1.4.1.311.10.3.24"
#define szOID_WINDOWS_THIRD_PARTY_COMPONENT_SIGNER "1.3.6.1.4.1.311.10.3.25"
#define szOID_WINDOWS_SOFTWARE_EXTENSION_SIGNER "1.3.6.1.4.1.311.10.3.26"
#define szOID_DISALLOWED_LIST "1.3.6.1.4.1.311.10.3.30"
#define szOID_PIN_RULES_SIGNER "1.3.6.1.4.1.311.10.3.31"
#define szOID_PIN_RULES_CTL "1.3.6.1.4.1.311.10.3.32"
#define szOID_PIN_RULES_EXT "1.3.6.1.4.1.311.10.3.33"
#define szOID_PIN_RULES_DOMAIN_NAME "1.3.6.1.4.1.311.10.3.34"
#define szOID_PIN_RULES_LOG_END_DATE_EXT "1.3.6.1.4.1.311.10.3.35"
#define szOID_IUM_SIGNING "1.3.6.1.4.1.311.10.3.37"
#define szOID_EV_WHQL_CRYPTO "1.3.6.1.4.1.311.10.3.39"
#define szOID_BIOMETRIC_SIGNING "1.3.6.1.4.1.311.10.3.41"
#define szOID_ENCLAVE_SIGNING "1.3.6.1.4.1.311.10.3.42"
#define szOID_SYNC_ROOT_CTL_EXT "1.3.6.1.4.1.311.10.3.50"
#define szOID_HPKP_DOMAIN_NAME_CTL "1.3.6.1.4.1.311.10.3.60"
#define szOID_HPKP_HEADER_VALUE_CTL "1.3.6.1.4.1.311.10.3.61"
#define szOID_KP_KERNEL_MODE_HAL_EXTENSION_SIGNING "1.3.6.1.4.1.311.61.5.1"
#define szOID_WINDOWS_STORE_SIGNER "1.3.6.1.4.1.311.76.3.1"
#define szOID_DYNAMIC_CODE_GEN_SIGNER "1.3.6.1.4.1.311.76.5.1"
#define szOID_MICROSOFT_PUBLISHER_SIGNER "1.3.6.1.4.1.311.76.8.1"
#define szOID_YESNO_TRUST_ATTR "1.3.6.1.4.1.311.10.4.1"
#define szOID_SITE_PIN_RULES_INDEX_ATTR "1.3.6.1.4.1.311.10.4.2"
#define szOID_SITE_PIN_RULES_FLAGS_ATTR "1.3.6.1.4.1.311.10.4.3"

void CreateInfoOutPut(PS_CREATE_INFO CreateInfo);
void SectionImageInfomationOutPut(SECTION_IMAGE_INFORMATION SectionImageInfomation);
void BaseCreateProcessMessageOutPut(BASE_SXS_CREATEPROCESS_MSG BaseCreateProcessMessageSxs);
NTSTATUS ValidateAppExecutionAliasRedirectPackageIdentity(IN HANDLE KeyHandle, IN ExtendedAppExecutionAliasInfo_New * AppExecutionAliasInfo);
NTSTATUS  BasepConvertWin32AttributeList(
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	BOOLEAN ConvertType, //BOOLEAN IsCreateThread
	PULONG ExtendedFlags,
	PUNICODE_STRING PackageFullName,
	PSECURITY_CAPABILITIES * SecurityCapabilities,
	BOOLEAN * HasHandleList,
	PHANDLE ParentProcessHandle,
	CONSOLE_REFERENCE * ConsoleHandleInfo,
	PPS_MITIGATION_OPTIONS_MAP MitigationOptions,
	PPS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptions,
	PWIN32K_SYSCALL_FILTER Win32kFilter,//11
	...
	//PULONG AllApplicationPackagesPolicy,//12
	//PULONG ComponentFilter,
	//PMAXVERSIONTESTED_INFO MaxVersionTested,
	//PPS_BNO_ISOLATION_PARAMETERS BnoIsolation,
	//DWORD * DesktopAppPolicy,
	//PISOLATION_MANIFEST_PROPERTIES IsolationManifest,
	//PUNICODE_STRING UnknowStringProcThread20,//
	//ULONG_PTR * UnknowPVOIDProcThread21,//
	//PPS_TRUSTLET_CREATE_ATTRIBUTES TrustletAttributes,
	//PULONG ProcessFlags,//
	//PPS_ATTRIBUTE_LIST AttributeList,
	//PULONG AttributeListCount,
	//IN OPTIONAL ULONG ProcThreadAttributeMaxCount
);


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
	PHANDLE hRestrictedUserToken
);



#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)
#define DefaultComSpecPath L"\\system32\\cmd.exe"
#define DefaultComSpecPathStringCount (sizeof(DefaultComSpecPath) - sizeof(UNICODE_NULL)) / sizeof(WCHAR)
// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())


#define KI_USER_SHARED_DATA 0x7FFE0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)
//#define GetCurrentTickCount() ((DWORD)((SharedUserData->TickCountMultiplier * (ULONGLONG)SharedUserData->TickCount.LowPart) >> 24))

PVOID BasepIsRealtimeAllowed(BOOLEAN LeaveEnabled, BOOLEAN Impersonating);

typedef NTSTATUS(NTAPI* BasepIsProcessAllowed_)(IN LPWSTR ApplicationName);
typedef BOOL(NTAPI* BaseUpdateVDMEntry_)(
	IN ULONG UpdateIndex,
	IN OUT HANDLE* WaitHandle,
	IN ULONG IndexInfo,
	IN ULONG BinaryType
	);
typedef NTSTATUS(NTAPI* BasepCheckWebBladeHashes_)(HANDLE FileHandle);

PRTL_USER_PROCESS_PARAMETERS BasepCreateProcessParameters(
	IN  LPCWSTR lpApplicationName,
	IN  PUNICODE_STRING ImageName,
	IN  LPCWSTR CurrentDirectory,
	IN  PWSTR CommandLine,
	IN  LPCWSTR AppXDllDirectory,
	IN  LPCWSTR AppXRedirectionDllName,
	IN  BOOLEAN IsPackageProcess,
	IN  PVOID Environment,
	IN OUT LPSTARTUPINFOW StartInfo,
	IN  ULONG dwCreationFlags,
	IN  BOOL DefaultInheritOnly,
	IN  ULONG ProcessFlags,
	IN  PCONSOLE_REFERENCE ConsoleReference,
	IN  HANDLE ParentProcessHandle
);

typedef HANDLE(NTAPI* BaseGetConsoleReference_)(void);
typedef DWORD(WINAPI* BaseSetLastNTError_)(IN NTSTATUS Status);

EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlCreateProcessParametersWithTemplate(PRTL_USER_PROCESS_PARAMETERS* ProcessParameters, PRTL_USER_PROCESS_PARAMETERS Template, ULONG Flags);
EXTERN_C NTSYSAPI NTSTATUS NTAPI LdrGetDllDirectory(PUNICODE_STRING DllDirectory);

EXTERN_C NTSYSAPI DWORD NTAPI RtlSetLastWin32Error(IN LONG LastError);

EXTERN_C NTSYSAPI NTSTATUS NTAPI DbgUiConnectToDbg(void);
EXTERN_C NTSYSAPI HANDLE NTAPI DbgUiGetThreadDebugObject(void);

EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlDestroyEnvironment(PVOID Environment);

EXTERN_C NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
	IN  PCWSTR DosPathName,
	OUT PUNICODE_STRING NtPathName,
	OUT PWSTR* NtFileNamePart OPTIONAL,
	OUT PCURDIR DirectoryInfo OPTIONAL
);

EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlGetExePath(PCWSTR name, PWSTR* path);
EXTERN_C NTSYSAPI BOOLEAN NTAPI RtlReleasePath(PWSTR Path);

EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlInitUnicodeStringEx(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);
EXTERN_C NTSYSAPI VOID NTAPI RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);

EXTERN_C NTSYSAPI RTL_PATH_TYPE NTAPI RtlDetermineDosPathNameType_U(PCWSTR Path);
EXTERN_C NTSYSAPI PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
EXTERN_C NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
EXTERN_C NTSYSAPI ULONG NTAPI RtlIsDosDeviceName_U(PCWSTR DosFileName);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UstrEx(PUNICODE_STRING FileName, PUNICODE_STRING StaticString, PUNICODE_STRING DynamicString, PUNICODE_STRING* StringUsed, PSIZE_T FilePartSize, PBOOLEAN NameInvalid, RTL_PATH_TYPE* PathType, PSIZE_T LengthNeeded);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlCreateEnvironmentEx(PVOID SourceEnv, PVOID* Environment, ULONG Flags);
EXTERN_C NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID BaseAddress);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlWow64GetProcessMachines(HANDLE process, USHORT* CurrentMachine, USHORT* TargetMachine);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

EXTERN_C NTSYSAPI NTSTATUS NTAPI LdrQueryImageFileKeyOption(
	HANDLE KeyHandle,
	PCWSTR ValueName,
	ULONG Type,
	LPCWSTR Buffer,
	ULONG BufferSize,
	PULONG ReturnedLength
);

EXTERN_C NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
	IN PSID Sid1,
	IN PSID Sid2
);

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
	OUT PUNICODE_STRING UnicodeString,
	IN  PSID Sid,
	IN  BOOLEAN AllocateDestinationString
);

EXTERN_C NTSYSAPI
PULONG
NTAPI
RtlSubAuthoritySid(
	_In_ PSID Sid,
	_In_ ULONG SubAuthority
);

EXTERN_C NTSYSAPI
PVOID
NTAPI
RtlFreeSid(
	IN PSID Sid
);

EXTERN_C NTSYSAPI
ULONG
NTAPI
RtlLengthRequiredSid(
	_In_ ULONG SubAuthorityCount
);

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
RtlGetAppContainerSidType(
	_In_ PSID AppContainerSid,
	_Out_ PAPPCONTAINER_SID_TYPE AppContainerSidType
);

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
RtlGetAppContainerParent(
	_In_ PSID AppContainerSid,
	_Out_ PSID* AppContainerSidParent // RtlFreeSid
);

EXTERN_C NTSYSAPI
ULONG
NTAPI
RtlGetCurrentServiceSessionId(
	VOID
);


#define RTL_ACQUIRE_PRIVILEGE_REVERT 0x00000001
#define RTL_ACQUIRE_PRIVILEGE_PROCESS 0x00000002

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
RtlAcquirePrivilege(
	_In_ PULONG Privilege,
	_In_ ULONG NumPriv,
	_In_ ULONG Flags,
	_Out_ PVOID* ReturnedState
);


EXTERN_C NTSYSAPI
VOID
NTAPI
RtlReleasePrivilege(
	_In_ PVOID StatePointer
);

typedef BOOL(WINAPI* BuildSubSysCommandLine_)(
	ULONG  Type,
	LPCWSTR NewCommandLine,
	ULONG_PTR Reserved,
	LPCWSTR RawCommandLine,
	PUNICODE_STRING SubSysCommandLine
	);
typedef HANDLE(WINAPI* BasepGetConsoleHost_)();

typedef NTSTATUS(WINAPI* BasepConvertWin32AttributeList_)(
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	BOOLEAN ConvertType, //BOOLEAN IsCreateThread
	PULONG ExtendedFlags,
	PUNICODE_STRING PackageFullName,
	PSECURITY_CAPABILITIES* SecurityCapabilities,
	BOOLEAN* HasHandleList,
	PHANDLE ParentProcessHandle,
	CONSOLE_REFERENCE* ConsoleHandleInfo,
	PPS_MITIGATION_OPTIONS_MAP MitigationOptions,
	PPS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptions,
	PWIN32K_SYSCALL_FILTER Win32kFilter,
	...
	);

typedef NTSTATUS(WINAPI* BasepQueryAppCompat_)(
	PSECTION_IMAGE_INFORMATION SectionImageInfomation,
	BOOL AddressSpaceOverride,
	USHORT ProcessorArchitecture,
	HANDLE FileHandle,
	HANDLE ProcessHandle,
	PWSTR Win32ImageName,
	PVOID Environment,
	PUNICODE_STRING PackageFullName,
	PSDBQUERYRESULT* SdbQueryResult,
	DWORD* SdbQueryResultSize,
	PVOID* AppCompatSxsData,
	DWORD* AppCompatSxsDataSize,
	ULONG* dwFusionFlags,             // 13
	COAMPAT_FIX_FLAG* dwLuaRunlevelFlags,            // 14 ULONGLONG
	DWORD* dwInstallerFlags,             // 15
	USHORT* ImageMachine,
	PMAXVERSIONTESTED_INFO MaxVersionTested, //PackageOnly
	DWORD* DeviceFamilyID //PackageOnly
	);
typedef NTSTATUS(WINAPI* BasepGetAppCompatData_)(
	PWSTR Win32ImagePath,
	PWSTR PackageName,
	DWORD* ElevationFlags,
	PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel,// ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION
	PSUPPORTED_OS_INFO SxsSupportedOSMajorVersion,
	ULONGLONG* SxsMaxVersionTested,
	PSECTION_IMAGE_INFORMATION SectionImageInfomation,
	USHORT AppCompatImageMachine,
	ULONGLONG MaxVersionTested,
	DWORD DeviceFamilyID,
	PSDBQUERYRESULT* SdbQueryResult,
	DWORD* SdbQueryResultSize,
	PVOID* AppCompatData,
	DWORD* AppCompatDataSize
	);
typedef BOOL(WINAPI* BasepInitAppCompatData_)(
	HANDLE ProcessHandle,
	PVOID AppCompatData,
	DWORD AppCompatDataSize
	);

NTSTATUS BasepUpdateProcessParametersField(
	IN HANDLE ProcessHandle,
	IN LPVOID* ValuePointer,//ULONGLONG*
	IN SIZE_T NumberOfBytesToWrite,
	IN LPVOID* Wow64ValuePointer,//ULONG*
	IN ULONGLONG ProcessParametersOffset,
	IN ULONG ProcessParametersWow64Offset,
	IN PPS_CREATE_INFO CreateInfo);


typedef NTSTATUS(WINAPI* BaseCheckElevation_)(
	IN HANDLE ProcessHandle,
	IN HANDLE FileHandle,
	IN LPCWSTR Win32ImagePath,
	IN OUT DWORD* BaseElevationFlags,
	IN COAMPAT_FIX_FLAG dwLuaRunlevelFlags,  //AppCompatFixFlags ULONGLONG
	IN OUT PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel,
	IN PUNICODE_STRING AssemblyName,
	IN DWORD dwInstallerFlags,
	IN HANDLE TokenHandle,
	OUT DWORD* pdwRunLevel,
	OUT DWORD* pdwElevateReason
	);
typedef LONG(WINAPI* BasepGetPackageActivationTokenForSxS_)(
	PVOID PackageActivationSxsInfo,
	HANDLE TokenHandle,
	PHANDLE ActivationToken
	);

typedef LONG(WINAPI* BasepGetPackageActivationTokenForSxS2_)(
	PVOID PackageActivationSxsInfo,
	HANDLE TokenHandle,
	PACTIVATION_TOKEN_INFO ActivationTokenInfo
	);

//LONG ULONG
typedef DWORD(WINAPI* BasepFreeActivationTokenInfo_)(PACTIVATION_TOKEN_INFO ActivationTokenInfo);

typedef LONG(WINAPI* GetPackageFullNameFromToken__)(
	_In_ HANDLE token,
	_Inout_ UINT32* packageFullNameLength,
	_Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName
	);
typedef NTSTATUS(NTAPI* BaseWriteErrorElevationRequiredEvent_)(void);

typedef NTSTATUS(NTAPI* BaseElevationPostProcessing_)(DWORD ElevationFlags, USHORT ProcessorArchitecture, HANDLE ProcessHandle);
typedef VOID(NTAPI* RtlGetDeviceFamilyInfoEnum_)(
	_Out_opt_ ULONGLONG* pullUAPInfo,
	_Out_opt_ DWORD* pulDeviceFamily,
	_Out_opt_ DWORD* pulDeviceForm
	);

typedef NTSTATUS(WINAPI* BasepCreateLowBox_)(HANDLE TokenHandle, PSECURITY_CAPABILITIES SecurityCapabilities, PHANDLE LowBoxToken);
BOOL BasepAdjustApplicationPath(IN OUT PUNICODE_STRING ApplicationPath);
typedef NTSTATUS(WINAPI* CheckAppXPackageBreakaway_)(PWSTR Buffer, PBOOL UnknowAppXPackageBreakaway);

/*
NTSTATUS(WINAPI* LoadAppExecutionAliasInfoForExecutable_)(
	PWSTR DosPath,
	HANDLE TokenHandle,
	HANDLE AliasHeap,
	ExtendedAppExecutionAliasInfo** AppExecutionAliasInfo);
*/
NTSTATUS LoadAppExecutionAliasInfoForExecutable(
	IN  HANDLE KeyHandle,
	IN  PWSTR Win32ImagePath,
	IN  HANDLE TokenHandle,
	IN  HANDLE HeapHandle,
	OUT	ExtendedAppExecutionAliasInfo** lppAppExecutionAliasInfo);

typedef LONG(WINAPI* GetAppExecutionAliasPath_)(PWSTR Win32ImagePath, HANDLE TokenHandle, PWSTR OutAliasFullPath, DWORD* Length);
typedef LONG(WINAPI* GetAppExecutionAliasPathEx_)(PWSTR Win32ImagePath, PWSTR SpecialAliasPackagesDirectory, HANDLE TokenHandle, PWSTR OutAliasFullPath, DWORD* Length);


typedef NTSTATUS(WINAPI* LoadAppExecutionAliasInfoEx_)(PWSTR DosPath, HANDLE TokenHandle, ExtendedAppExecutionAliasInfo** AppExecutionAliasInfo);
NTSTATUS ValidateAppXAliasFallback(LPCWSTR RawBaseImagePath, ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo);
typedef VOID(WINAPI* BasepReleaseAppXContext_)(PVOID AppXContent);
typedef BOOLEAN(WINAPI* BasepFreeAppCompatData_)(PVOID AppCompatData, PVOID AppCompatSxsData, PVOID SdbQueryResult);
typedef BOOLEAN(WINAPI* BasepReleaseSxsCreateProcessUtilityStruct_)(PSXS_CREATEPROCESS_UTILITY SxsCreateProcessUtilityStruct);

//typedef BOOLEAN(WINAPI* BasepFreeBnoIsolationParameter_)(PPS_BNO_ISOLATION_PARAMETERS BnoIsolationParameter);
BOOLEAN BasepFreeBnoIsolationParameter(PPS_BNO_ISOLATION_PARAMETERS BnoIsolationParameter);
NTSTATUS BasepFreeActivationTokenInfo(PACTIVATION_TOKEN_INFO lpActivationTokenInfo);

VOID BasepAddToOrUpdateAttributesList(
	PPS_ATTRIBUTE_LIST AttributeListSource,
	ULONG AttributeListSourceCount,
	PPS_ATTRIBUTE_LIST AttributeListDest,
	PULONG AttributeListDestCount);

typedef NTSTATUS(WINAPI* BaseFormatObjectAttributes_)(
	POBJECT_ATTRIBUTES LocalObjectAttributes,
	LPSECURITY_ATTRIBUTES SecurityAttributes,
	PUNICODE_STRING ObjectName,
	POBJECT_ATTRIBUTES* ObjectAttributes
	);

NTSTATUS BasepCreateBnoIsolationObjectDirectories(IN HANDLE TokenHandle, IN OUT PPS_BNO_ISOLATION_PARAMETERS BnoIsolation);


typedef NTSTATUS(WINAPI* GetEmbeddedImageMitigationPolicy_)(
	PISOLATION_MANIFEST_PROPERTIES IsolationManifest,
	PPS_MITIGATION_OPTIONS_MAP MitigationOptions,
	PWIN32K_SYSCALL_FILTER Win32kFilter,
	PBOOL ParseIsolationManifestSuccess
	);
typedef NTSTATUS(WINAPI* BasepAppXExtension_)(
	HANDLE TokenHandle,
	PUNICODE_STRING PackageFullName,
	PSECURITY_CAPABILITIES SecurityCapabilities,
	PVOID Environment,
	PAPPX_PROCESS_CONTEXT* AppXProcessContext,
	PVOID AppXEnvironment
	);

typedef NTSTATUS(WINAPI* BasepAppContainerEnvironmentExtension_)(PSID AppContainerSid, PVOID Environment, PVOID* AppXEnvironmentExtension);

typedef NTSTATUS(WINAPI* BasepGetPackagedAppInfoForFile_)(LPCWSTR PackageImagePath, HANDLE TokenHandle, BOOL IsCreateProcess, ExtendedPackagedAppContext::ExtendedPackagedAppContext** lppExtendedPackagedAppContext);

typedef NTSTATUS(WINAPI* AppModelPolicy_GetPolicy_Internal_)(
	HANDLE TokenHandle,
	AppModelPolicy_Type ModelPolicy_Type,
	PULONG ModelPolicy_Value,
	PPS_PKG_CLAIM PkgClaim,
	PULONG_PTR AttributesPresent
	);

typedef BOOL(WINAPI* BaseIsDosApplication_)(PUNICODE_STRING NtImageName);
typedef NTSTATUS(WINAPI* BasepCheckWinSaferRestrictions_)(HANDLE TokenHandle, LPCWSTR lpApplicationName, HANDLE FileHandle, PUNICODE_STRING PackageFullName);
typedef BOOLEAN(WINAPI* ApiSetCheckFunction)(void);



typedef PULONG(WINAPI* KernelBaseGetGlobalData_)(void);
typedef VOID(WINAPI* RaiseInvalid16BitExeError_)(PUNICODE_STRING NtImageName);

typedef BOOL(WINAPI* BasepProcessInvalidImage_)(
	NTSTATUS Error,
	HANDLE TokenHandle,
	LPCWSTR Win32ImageName,
	LPCWSTR* lppApplicationName,
	PWSTR* lpCommandLine,
	LPCWSTR lpCurrentDirectory,
	PULONG dwCreationFlags,
	PBOOL bInheritHandles,
	PUNICODE_STRING NtPathName,
	BOOLEAN* IsWowBinary,
	PVOID lpEnvironment,
	LPSTARTUPINFOW StartInfo,
	PBASE_API_MSG ApiMessage,
	PULONG VDMTaskId,
	PUNICODE_STRING SubSysCommandLine,
	ANSI_STRING* AnsiStringVDMEnv,
	UNICODE_STRING* UnicodeStringVDMEnv,
	PULONG VDMCreationState, //BYTE*?
	PULONG VdmBinaryType,
	BOOL* VdmPartiallyCreated,
	PHANDLE VdmWaitHandle
	);

typedef BOOL(WINAPI* NtVdm64CreateProcessInternalW_)(
	HANDLE hToken,
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
	PHANDLE hRestrictedUserToken
	);

//AppXPostSuccessExtension
typedef NTSTATUS(WINAPI* BasepPostSuccessAppXExtension_)(HANDLE ProcessHandle, PAPPX_PROCESS_CONTEXT AppXContext);

typedef NTSTATUS(WINAPI* CompletePackagedProcessCreationEx_)(
	HANDLE ProcessHandle,
	HANDLE ThreadHandle,
	BOOL IsConsoleUWPApp,
	BOOL IsMultipleInstancesUWPApp,
	LPCWSTR lpCurrentDirectory,
	LPCWSTR lpCommandLine,
	BOOL IsAppExecutionAliasType,
	HANDLE TokenHandle,
	PULONG AppResumeRequired
	);


typedef NTSTATUS(WINAPI* CompleteAppExecutionAliasProcessCreationEx_)(
	HANDLE ProcessHandle,
	HANDLE ThreadHandle,
	BOOL UWPLaunchMode,
	LPCWSTR lpCurrentDirectory,
	LPCWSTR lpCommandLine,
	HANDLE TokenHandle,
	PULONG AppResumeRequired
	);

typedef NTSTATUS(WINAPI* BasepFinishPackageActivationForSxS_)(
	HANDLE ProcessHandle,
	HANDLE ThreadHandle,
	LPCWSTR lpCurrentDirectory,
	LPCWSTR lpCommandLine,
	HANDLE TokenHandle,
	PULONG AppResumeRequired
	);

typedef VOID(WINAPI* PerformAppxLicenseRundownEx_)(
	PWSTR AppXPackageName,
	HANDLE TokenHandle
	);

typedef VOID(WINAPI* BasepReleasePackagedAppInfo_)(ExtendedPackagedAppContext::ExtendedPackagedAppContext* ExtendedAppContext);
typedef VOID(WINAPI* FreeAppExecutionAliasInfoEx_)(ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo);
typedef BOOL(WINAPI* BaseDestroyVDMEnvironment_)(IN PANSI_STRING AnsiEnv, IN PUNICODE_STRING UnicodeEnv);

NTSTATUS BasepFreeActivationTokenInfo(PACTIVATION_TOKEN_INFO lpActivationTokenInfo);
NTSTATUS BasepCheckPplSupport(LPCWSTR szFilePath, BOOL* IsPplSupported);