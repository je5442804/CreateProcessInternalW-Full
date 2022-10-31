#pragma once
#define WIN32_NO_STATUS
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

void CreateInfoOutPut(PS_CREATE_INFO CreateInfo);
void SectionImageInfomationOutPut(SECTION_IMAGE_INFORMATION SectionImageInfomation);
void BaseCreateProcessMessageOutPut(BASE_SXS_CREATEPROCESS_MSG BaseCreateProcessMessageSxs);

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

typedef _Null_terminated_ wchar_t* NTSTRSAFE_PWSTR;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)

// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())


#define KI_USER_SHARED_DATA 0x7FFE0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)
//#define GetCurrentTickCount() ((DWORD)((SharedUserData->TickCountMultiplier * (ULONGLONG)SharedUserData->TickCount.LowPart) >> 24))

typedef DWORD(WINAPI* BaseSetLastNTError_)(IN NTSTATUS Status);

typedef DWORD(NTAPI* RtlSetLastWin32Error_)(IN ULONG LastError);

typedef VOID(NTAPI* RtlInitUnicodeString_)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

typedef NTSTATUS(NTAPI* RtlStringCchCatW_)(_Inout_updates_(cchDest) _Always_(_Post_z_) NTSTRSAFE_PWSTR 	pszDest,
	_In_ SIZE_T 	cchDest,
	_In_ LPCWSTR 	pszSrc
	);


typedef NTSTATUS(NTAPI* RtlGetVersion_)(POSVERSIONINFOEXW lpVersionInformation);

typedef PVOID(WINAPI* BasepIsRealtimeAllowed_)(BOOLEAN LeaveEnabled, BOOLEAN Impersonating);
typedef NTSTATUS(NTAPI* BasepIsProcessAllowed_)(IN LPWSTR ApplicationName);
typedef BOOL(NTAPI* BaseUpdateVDMEntry_)(
	IN ULONG UpdateIndex,
	IN OUT HANDLE* WaitHandle,
	IN ULONG IndexInfo,
	IN ULONG BinaryType
	);
typedef NTSTATUS(NTAPI* BasepCheckWebBladeHashes_)(HANDLE FileHandle);
typedef NTSTATUS(NTAPI* RtlDestroyProcessParameters_)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
typedef PRTL_USER_PROCESS_PARAMETERS(NTAPI* BasepCreateProcessParameters_)(
	PCWSTR WindowTitle,
	PUNICODE_STRING ImageName,
	LPCWSTR CurrentDirectory,
	PWSTR CommandLine,
	LPCWSTR AppXDllDirectory,
	LPCWSTR AppXRedirectionDllName,
	BOOLEAN IsPackage,//BOOLEAN
	PVOID Environment,
	LPSTARTUPINFOW StartInfo,
	ULONG dwCreationFlags,
	BOOL DefaultInheritOnly,
	ULONG ProcessFlags,
	PCONSOLE_HANDLE_INFO ConsoleHandle,
	HANDLE ParentProcessHandle
	);

typedef NTSTATUS(NTAPI* DbgUiConnectToDbg_)(void);

typedef HANDLE(NTAPI* DbgUiGetThreadDebugObject_)(void);


typedef VOID(NTAPI* RtlDestroyEnvironment_)(PWSTR Environment);

typedef BOOLEAN(NTAPI* RtlDosPathNameToNtPathName_U_)(PCWSTR DosPathName, PUNICODE_STRING NtPathName, PCWSTR* NtFileNamePart, PVOID DirectoryInfo);
typedef NTSTATUS(WINAPI* RtlGetExePath_)(PCWSTR name, PWSTR* path);
typedef BOOLEAN(WINAPI* RtlReleasePath_)(PWSTR Path);
typedef NTSTATUS(WINAPI* RtlInitUnicodeStringEx_)(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);
typedef NTSTATUS(WINAPI* RtlFreeUnicodeString_)(PUNICODE_STRING UnicodeString);
typedef RTL_PATH_TYPE(WINAPI* RtlDetermineDosPathNameType_U_)(PCWSTR Path);
typedef PVOID(WINAPI* RtlAllocateHeap_)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef BOOLEAN(WINAPI* RtlFreeHeap_)(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
typedef ULONG(WINAPI* RtlIsDosDeviceName_U_)(PCWSTR DosFileName);
typedef NTSTATUS(WINAPI* RtlGetFullPathName_UstrEx_)(PUNICODE_STRING FileName, PUNICODE_STRING StaticString, PUNICODE_STRING DynamicString, PUNICODE_STRING* StringUsed, PSIZE_T FilePartSize, PBOOLEAN NameInvalid, RTL_PATH_TYPE* PathType, PSIZE_T LengthNeeded);
typedef NTSTATUS(WINAPI* RtlCreateEnvironmentEx_)(PVOID SourceEnv, PVOID* Environment, ULONG Flags);
typedef PIMAGE_NT_HEADERS(WINAPI* RtlImageNtHeader_)(PVOID BaseAddress);
typedef NTSTATUS(WINAPI* RtlWow64GetProcessMachines_)(HANDLE process, USHORT* CurrentMachine, USHORT* TargetMachine);

typedef NTSTATUS(WINAPI* LdrQueryImageFileKeyOption_)(
	HANDLE KeyHandle,
	PCWSTR ValueName,
	ULONG Type,
	LPCWSTR Buffer,
	ULONG BufferSize,
	PULONG ReturnedLength
	);
typedef BOOL(WINAPI* BuildSubSysCommandLine_)(
	ULONG  Type,
	LPCWSTR NewCommandLine,
	ULONG_PTR Reversed,
	LPCWSTR RawCommandLine,
	PUNICODE_STRING SubSysCommandLine
	);
typedef HANDLE(WINAPI* BasepGetConsoleHost_)();
typedef NTSTATUS(WINAPI* BasepConvertWin32AttributeList_)(
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	BOOLEAN IsThread,
	PULONG ExtendedFlags,
	PUNICODE_STRING PackageFullName,
	PSECURITY_CAPABILITIES* SecurityCapabilities,
	BOOLEAN* HasHandleList,
	PHANDLE ParentProcessHandle,
	CONSOLE_HANDLE_INFO* ConsoleHandleInfo,
	PPS_MITIGATION_OPTIONS_MAP MitigationOptions,
	PPS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptions,
	PWIN32K_SYSCALL_FILTER Win32kFilter,
	PULONG ComponentFilter,
	PMAXVERSIONTESTED_INFO MaxVersionTested,
	PPS_BNO_ISOLATION_PARAMETERS BnoIsolation,
	DWORD* DesktopAppPolicy,
	PISOLATION_MANIFEST_PROPERTIES IsolationManifest,
	PUNICODE_STRING PackageFullName2,
	PPS_TRUSTLET_ATTRIBUTE_DATA Trustlet,
	PPS_ATTRIBUTE_LIST AttributeList,
	PULONG AttributeListCount,
	ULONG ProcThreadAttributeMax
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
	PVOID* AppCompatCacheData,
	DWORD* AppCompatCacheDataSize,
	PVOID* AppCompatSxsData,
	DWORD* AppCompatSxsDataSize,
	BOOL* AppCompatSxsSafeMode,             // 13
	ULONGLONG* AppCompatPrivilegeFlags,            // 14
	DWORD* UnknowCompatCache3,             // 15
	USHORT* ImageMachine,
	PMAXVERSIONTESTED_INFO MaxVersionTested, //PackageOnly
	DWORD* DeviceFamilyID //PackageOnly
	);
typedef NTSTATUS(WINAPI* BasepGetAppCompatData_)(
	PWSTR Win32ImagePath,
	PWSTR PackageName,
	DWORD* ElevationFlags,
	PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel,// ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION
	PULONG SxsSupportedOSMajorVersion,
	ULONGLONG* SxsMaxVersionTested,
	PSECTION_IMAGE_INFORMATION SectionImageInfomation,
	USHORT AppCompatImageMachine,
	ULONGLONG MaxVersionTested,
	DWORD DeviceFamilyID,
	PVOID* AppCompatCacheData, //AppCompatCacheData
	DWORD* AppCompatCacheDataSize,
	PVOID* AppCompatData,
	DWORD* AppCompatDataSize
	);
typedef BOOL(WINAPI* BasepInitAppCompatData_)(
	HANDLE ProcessHandle,
	PVOID AppCompatData,
	DWORD AppCompatDataSize
	);

typedef NTSTATUS(WINAPI* BasepUpdateProcessParametersField_)(
	IN HANDLE ProcessHandle,
	IN PVOID ValuePointer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PVOID ValueFix,//???????
	IN ULONGLONG ProcessParametersOffset,
	IN ULONG ProcessParametersWow64Offset,
	IN PPS_CREATE_INFO CreateInfo
	);
typedef NTSTATUS(WINAPI* BaseCheckElevation_)(
	IN HANDLE ProcessHandle,
	IN HANDLE FileHandle,
	IN LPCWSTR Win32ImagePath,
	IN OUT DWORD* BaseElevationFlags,
	IN ULONGLONG AppCompatPrivilegeFlags,
	IN OUT PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel,
	IN PUNICODE_STRING AssemblyIdentity,
	IN DWORD UnknowCompatCache3,
	IN HANDLE TokenHandle,
	OUT DWORD* RunLevel,
	OUT DWORD* ElevateReason
	);
typedef DWORD(WINAPI* BasepGetPackageActivationTokenForSxS_)(
	PVOID PackageActivationSxsInfo,
	HANDLE TokenHandle,
	PHANDLE ActivationToken
	);
typedef LONG(WINAPI* GetPackageFullNameFromToken_)(
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
typedef BOOL(WINAPI* BasepAdjustApplicationPath_)(PUNICODE_STRING ApplicationPath);
typedef NTSTATUS(WINAPI* CheckAppXPackageBreakaway_)(PWSTR Buffer, PBOOL UnknowAppXPackageBreakaway);

typedef NTSTATUS(WINAPI* LoadAppExecutionAliasInfoForExecutable_)(
	PWSTR DosPath,
	HANDLE TokenHandle,
	HANDLE ProcessHeap,
	ExtendedAppExecutionAliasInfo** AppExecutionAliasInfo);
typedef DWORD(WINAPI* GetAppExecutionAliasPath_)(PWSTR Win32ImagePath, HANDLE TokenHandle, PWSTR OutAliasPath, DWORD* Length);
typedef NTSTATUS(WINAPI* LoadAppExecutionAliasInfoEx_)(PWSTR DosPath, HANDLE TokenHandle, ExtendedAppExecutionAliasInfo** AppExecutionAliasInfo);
typedef NTSTATUS(WINAPI* ValidateAppXAliasFallback_)(LPCWSTR lpFileName, PVOID AppExecutionAliasInfo);
typedef VOID(WINAPI* BasepReleaseAppXContext_)(PVOID AppXContent);
typedef BOOLEAN(WINAPI* BasepFreeAppCompatData_)(PVOID AppCompatData, PVOID AppCompatSxsData, PVOID AppCompatCacheData);
typedef BOOLEAN(WINAPI* BasepReleaseSxsCreateProcessUtilityStruct_)(PSXS_CREATEPROCESS_UTILITY SxsCreateProcessUtilityStruct);
typedef BOOLEAN(WINAPI* BasepFreeBnoIsolationParameter_)(PPS_BNO_ISOLATION_PARAMETERS BnoIsolationParameter);

typedef VOID(WINAPI* CsrFreeCaptureBuffer_)(PCSR_CAPTURE_BUFFER CaptureBuffer);

typedef NTSTATUS(WINAPI* BaseFormatObjectAttributes_)(
	POBJECT_ATTRIBUTES LocalObjectAttributes,
	LPSECURITY_ATTRIBUTES SecurityAttributes,
	PUNICODE_STRING ObjectName,
	POBJECT_ATTRIBUTES* ObjectAttributes
	);
typedef VOID(WINAPI* BasepAddToOrUpdateAttributesList_)(PPS_ATTRIBUTE_LIST AttributeListSource, ULONG AttributeListSourceCount, PPS_ATTRIBUTE_LIST AttributeListDest, PULONG AttributeListDestCount);

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
typedef NTSTATUS(WINAPI* BasepCreateBnoIsolationObjectDirectories_)(HANDLE TokenHandle, PPS_BNO_ISOLATION_PARAMETERS BnoIsolation);


typedef NTSTATUS(WINAPI* AppModelPolicy_GetPolicy_Internal_)(
	HANDLE TokenHandle,
	AppModelPolicy_Type ModelPolicy_Type,
	PULONG ModelPolicy_Value,
	PPS_PKG_CLAIM PkgClaim,
	PULONG_PTR AttributesPresent
	);

typedef BOOL(WINAPI* BaseIsDosApplication_)(PUNICODE_STRING NtImageName);
typedef NTSTATUS(WINAPI* BasepCheckWinSaferRestrictions_)(HANDLE TokenHandle, LPCWSTR lpApplicationName, HANDLE FileHandle, PUNICODE_STRING PackageFullName);
typedef BOOLEAN(WINAPI* IsPresentFunction)(void);

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


typedef NTSTATUS(WINAPI* CompleteAppExecutionAliasProcessCreationEx_)(
	HANDLE ProcessHandle1,
	HANDLE ThreadHandle1,
	DWORD UWPLaunchMode,
	LPCWSTR lpCurrentDirectory1,
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
typedef VOID(WINAPI* FreeAppExecutionAliasInfoEx_)(
	ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo
	);
typedef BOOL(WINAPI* BaseDestroyVDMEnvironment_)(IN PANSI_STRING AnsiEnv, IN PUNICODE_STRING UnicodeEnv);

