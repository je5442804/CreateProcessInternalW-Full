#define _USE_FULL_PROC_THREAD_ATTRIBUTE
#pragma once
#include <Windows.h>
#include <iostream>
#include <appmodel.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define IS_WIN32_HRESULT(x)	(((x) & 0xFFFF0000) == 0x80070000)
#define WIN32_FROM_HRESULT(hr)		(0x0000FFFF & (hr))
#define leave __leave

#define PtrHigh32(x) (ULONGLONG)((ULONGLONG)x & 0xFFFFFFFF00000000)
#define WOW64_POINTER(Type) ULONG
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define HANDLE_DETACHED_PROCESS     ((HANDLE)-1)
#define HANDLE_CREATE_NEW_CONSOLE   ((HANDLE)-2)
#define HANDLE_CREATE_NO_WINDOW     ((HANDLE)-3)

#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define BREAKAWAY_INHIBITED 0x20

//0x0497C7
//0x4E87C7
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800 // NtCreateProcessEx only 
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess, remove from NtCreateUserProcess since win 11 insider 26016?
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 // removed
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb

#define PROCESS_CREATE_FLAGS_PACKAGE_BREAKAWAY 0x00010000 // Mask only, Fake Flag, DO NOT use as real one in NtCreateUserProcess, Local Process is Package and call with Package Breakway ? No Inherit DllPath
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess win 11 22000?
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess
//PspAllocateProcess ImageExpansionMitigation: 0x2 = NoImageExpansion
//
#define PROCESS_CREATE_FLAGS_IMAGE_EXPANSION_MITIGATION_DISABLE	0x80000
// PspAllocateProcess->[UnknowMemoryFlags = NewProcess | 0x10]->MmCreateProcessAddressSpace->MiCreateSlabIdentity(struct _MI_PARTITION* MiPartition,&EProcess->MmSlabIdentity)
#define PROCESS_CREATE_FLAGS_PARTITION_CREATE_SLAB_IDENTITY 0x00400000 // NtCreateProcessEx & NtCreateUserProcess win 11 insider 26016 , requires SeLockMemoryPrivilege

//
// Define Attribute to opt out of matching All Application Packages
//
#define PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT                                 0x01

#define DESKTOP_APP_BREAKAWAY_ENABLED(DesktopAppPolicy)  !(DesktopAppPolicy & (PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE  | PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_DISABLE_PROCESS_TREE))
#define DESKTOP_APP_BREAKAWAY_DISABLE(DesktopAppPolicy) ((DesktopAppPolicy & (PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE  | PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE)) == PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_ENABLE_PROCESS_TREE )

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?

#define PROCESS_PRIORITY_CLASS_UNKNOWN 0
#define PROCESS_PRIORITY_CLASS_IDLE 1
#define PROCESS_PRIORITY_CLASS_NORMAL 2
#define PROCESS_PRIORITY_CLASS_HIGH 3
#define PROCESS_PRIORITY_CLASS_REALTIME 4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL 6

#define PRIORITY_CLASS_MASK (NORMAL_PRIORITY_CLASS|IDLE_PRIORITY_CLASS|                 \
                             HIGH_PRIORITY_CLASS|REALTIME_PRIORITY_CLASS|               \
                             BELOW_NORMAL_PRIORITY_CLASS|ABOVE_NORMAL_PRIORITY_CLASS)

#define RTL_CREATE_ENVIRONMENT_TRANSLATE 0x1 // translate from multi-byte to Unicode
#define RTL_CREATE_ENVIRONMENT_TRANSLATE_FROM_OEM 0x2 // translate from OEM to Unicode (Translate flag must also be set)
#define RTL_CREATE_ENVIRONMENT_EMPTY 0x4 // create empty environment block

#define IMAGE_FILE_MACHINE_HYBRID_X86        0x3A64  // Hybrid: x86

#define VDM_PARTIALLY_CREATED	    1
#define VDM_FULLY_CREATED	    2
#define VDM_BEING_REUSED	    4
#define VDM_CREATION_SUCCESSFUL     8

#define BINARY_TYPE_DOS 	    0x10
#define BINARY_TYPE_WIN16           0x20
#define BINARY_TYPE_SEPWOW          0x40

#define BINARY_SUBTYPE_MASK         0xF
#define BINARY_TYPE_DOS_EXE	    01
#define BINARY_TYPE_DOS_COM	    02
#define BINARY_TYPE_DOS_PIF         03
#define BINARY_TYPE_WOW_EX      128

#define VDM_NOT_PRESENT 	    1
#define VDM_PRESENT_NOT_READY	    2
#define VDM_PRESENT_AND_READY	    4 

#define VDM_STATE_MASK		    7 

// Update VDM entry indexes
#define UPDATE_VDM_UNDO_CREATION    0
#define UPDATE_VDM_PROCESS_HANDLE   1
#define UPDATE_VDM_HOOKED_CTRLC     2

// Activatable State // APPX_PACKEAGE_CREATE_SUSPENDED
// PsmRegisterApplicationProcess // Wait for Debugger
#define APPX_PACKEAGE_CREATE_SUSPENDED 0x1

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY)

#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_SET 0x0002
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)
#define SYMBOLIC_LINK_ALL_ACCESS_EX (STANDARD_RIGHTS_REQUIRED | 0xFFFF)

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE

//Uncorrected
typedef enum _DirectoryCreateFlags
{
	None,
	AlwaysInheritSecurity,
	FakeObjectRoot			// googleprojectzero: Only works in kernel mode. Shadow?
}DirectoryCreateFlags;

typedef struct _PROC_THREAD_ATTRIBUTE {
	ULONG_PTR Attribute;
	SIZE_T Size;
	ULONG_PTR Value;
} PROC_THREAD_ATTRIBUTE, * PPROC_THREAD_ATTRIBUTE;

// private
typedef struct _PROC_THREAD_ATTRIBUTE_LIST {
	ULONG PresentFlags;
	ULONG AttributeCount;
	ULONG LastAttribute;
	ULONG SpareUlong0;
	PPROC_THREAD_ATTRIBUTE ExtendedFlagsAttribute;
	_Field_size_(AttributeCount) PROC_THREAD_ATTRIBUTE Attributes[1];
} PROC_THREAD_ATTRIBUTE_LIST, * LPPROC_THREAD_ATTRIBUTE_LIST;

//ProcThreadAttributeValue
#define ProcThreadAttributePresentFlag(Attribute) (1 << Attribute)

typedef enum _PROC_THREAD_ATTRIBUTE_NUMEX {
	ProcThreadAttributeParentProcess = 0,
	ProcThreadAttributeExtendedFlags = 1,// in ULONG (EXTENDED_PROCESS_CREATION_FLAG_*)
	ProcThreadAttributeHandleList = 2,
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	ProcThreadAttributeGroupAffinity = 3,
	ProcThreadAttributePreferredNode = 4,
	ProcThreadAttributeIdealProcessor = 5,
	ProcThreadAttributeUmsThread = 6,
	ProcThreadAttributeMitigationPolicy = 7,
#endif
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	ProcThreadAttributePackageFullName = 8, // in WCHAR[] // since WIN8 20跟它很像
	ProcThreadAttributeSecurityCapabilities = 9,
	ProcThreadAttributeConsoleReference = 10, // BaseGetConsoleReference (kernelbase.dll)
#endif
	ProcThreadAttributeProtectionLevel = 11,
#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
	ProcThreadAttributeOsMaxVersionTested = 12, // in MAXVERSIONTESTED_INFO // since THRESHOLD // (from exe.manifest)
#endif
#if (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD)
	ProcThreadAttributeJobList = 13,
	ProcThreadAttributeChildProcessPolicy = 14,
	ProcThreadAttributeAllApplicationPackagesPolicy = 15,
	ProcThreadAttributeWin32kFilter = 16,
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
	ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	ProcThreadAttributeDesktopAppPolicy = 18,
	ProcThreadAttributeBnoIsolation = 19, // in PROC_THREAD_BNOISOLATION_ATTRIBUTE
#endif
	// 20 WCHAR/LPWSTR 不知道什么东西，还处理字符串结尾NULL的长度判断 UNICODE_STRING->Length & 1 ??? 
	// ProcThread 21 8字节大小，不知道啊
	// Pro
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
	ProcThreadAttributePseudoConsole = 22, // in HANDLE (HPCON) // since RS5
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_19H1)
	ProcThreadAttributeIsolationManifest = 23, // in ISOLATION_MANIFEST_PROPERTIES // rev (diversenok) // since 19H2+
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
	
	ProcThreadAttributeMitigationAuditPolicy = 24,
	ProcThreadAttributeMachineType = 25,
	ProcThreadAttributeComponentFilter = 26,
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
	ProcThreadAttributeEnableOptionalXStateFeatures = 27,
#endif
	ProcThreadAttributeCreateStore = 28,// ULONG // rev (diversenok)
	ProcThreadAttributeTrustedApp = 29
} PROC_THREAD_ATTRIBUTE_NUMEX;

#ifndef PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS
#define PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS \
    ProcThreadAttributeValue(ProcThreadAttributeExtendedFlags, FALSE, TRUE, TRUE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PACKAGE_FULL_NAME
#define PROC_THREAD_ATTRIBUTE_PACKAGE_FULL_NAME \
    ProcThreadAttributeValue(ProcThreadAttributePackageFullName, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE
#define PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE \
    ProcThreadAttributeValue(ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_OSMAXVERSIONTESTED
#define PROC_THREAD_ATTRIBUTE_OSMAXVERSIONTESTED \
    ProcThreadAttributeValue(ProcThreadAttributeOsMaxVersionTested, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM
#define PROC_THREAD_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    ProcThreadAttributeValue(ProcThreadAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_BNO_ISOLATION
#define PROC_THREAD_ATTRIBUTE_BNO_ISOLATION \
    ProcThreadAttributeValue(ProcThreadAttributeBnoIsolation, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_ISOLATION_MANIFEST
#define PROC_THREAD_ATTRIBUTE_ISOLATION_MANIFEST \
    ProcThreadAttributeValue(ProcThreadAttributeIsolationManifest, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_CREATE_STORE
#define PROC_THREAD_ATTRIBUTE_CREATE_STORE \
    ProcThreadAttributeValue(ProcThreadAttributeCreateStore, FALSE, TRUE, FALSE)
#endif
#ifndef PROC_THREAD_ATTRIBUTE_TRUSTED_APP
#define PROC_THREAD_ATTRIBUTE_TRUSTED_APP \
    ProcThreadAttributeValue(ProcThreadAttributeTrustedApp, FALSE, TRUE, FALSE)
#endif

// private 
#define EXTENDED_PROCESS_CREATION_FLAG_ELEVATION_HANDLED 0x00000001
#define EXTENDED_PROCESS_CREATION_FLAG_FORCELUA 0x00000002
#define EXTENDED_PROCESS_CREATION_FLAG_FORCE_BREAKAWAY 0x00000004 // requires SeTcbPrivilege // since WINBLUE

// LUA elevation support
#define ELEVATION_FLAG_TOKEN_CHECKS       0x00000001
#define ELEVATION_FLAG_VIRTUALIZATION     0x00000002
#define ELEVATION_FLAG_SHORTCUT_REDIR     0x00000004
#define ELEVATION_FLAG_NO_SIGNATURE_CHECK 0x00000008

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef LONG KPRIORITY, * PKPRIORITY;

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32, * PSTRING32;

typedef STRING32 UNICODE_STRING32, * PUNICODE_STRING32;

typedef STRING UTF8_STRING;
typedef PSTRING PUTF8_STRING;

typedef const STRING* PCSTRING;
typedef const ANSI_STRING* PCANSI_STRING;
typedef const OEM_STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING
{
	USHORT Length; //0
	USHORT MaximumLength;//2
	PWSTR  Buffer;//8
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef enum _RTL_PATH_TYPE {
	RtlPathTypeUnknown,
	RtlPathTypeUncAbsolute,//1
	RtlPathTypeDriveAbsolute,//2
	RtlPathTypeDriveRelative,//3
	RtlPathTypeRooted,//4
	RtlPathTypeRelative,//5
	RtlPathTypeLocalDevice,//6
	RtlPathTypeRootLocalDevice//7
}RTL_PATH_TYPE;

/*
typedef struct _RTL_BUFFER
{
	PUCHAR Buffer;
	PUCHAR StaticBuffer;
	SIZE_T Size;
	SIZE_T StaticSize;
	SIZE_T ReservedForAllocatedSize;
	PVOID ReservedForIMalloc;
} RTL_BUFFER, * PRTL_BUFFER;
typedef struct _RTL_UNICODE_STRING_BUFFER {
	UNICODE_STRING String;
	RTL_BUFFER     ByteBuffer;
	UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;
*/

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (PWSTR)s }

// Balanced tree node

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};
	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, * PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, * PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, * PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, * PKEY_SET_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, * PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, * PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, * PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, * PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, * PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, * PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, * PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, * PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, * PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, * PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, * PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, * PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, * PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, * PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, * PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, * PSEMAPHORE_INFORMATION_CLASS;


typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, * PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, * PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, * PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, * PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, * PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, * PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
{
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, * PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;
typedef enum _KEY_VALUE_INFORMATION_CLASS
{
	KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
	KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
	KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,  // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
	KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, * PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, * PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, * PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, * PIO_SESSION_STATE;

typedef const WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, * PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;//0
			SHORT TotalLength;//2
		} s1;
		ULONG Length;//0
	} u1;
	//4
	union
	{
		struct
		{
			SHORT Type;
			SHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	//8
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};

	ULONG_PTR MessageId;//24 shoudl be ULONG but I set ULONG_PTR ?
	//28
	union
	{
		ULONGLONG ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};//36[对齐40]
} PORT_MESSAGE, * PPORT_MESSAGE;//[40]

typedef struct _PORT_DATA_ENTRY
{
	PVOID Base;
	ULONG Size;
} PORT_DATA_ENTRY, * PPORT_DATA_ENTRY;

typedef struct _PORT_DATA_INFORMATION
{
	ULONG CountDataEntries;
	PORT_DATA_ENTRY DataEntries[1];
} PORT_DATA_INFORMATION, * PPORT_DATA_INFORMATION;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, * PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, * PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, * PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, * PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, * PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, * PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, * PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, * PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, * PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, * PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation, // q; SECTION_BASIC_INFORMATION
	SectionImageInformation, // q; SECTION_IMAGE_INFORMATION
	SectionRelocationInformation, // q; PVOID RelocationAddress // name:wow64:whNtQuerySection_SectionRelocationInformation
	SectionOriginalBaseInformation, // PVOID BaseAddress
	SectionInternalImageInformation, // SECTION_INTERNAL_IMAGE_INFORMATION // since REDSTONE2
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct _SECTION_BASIC_INFORMATION
{
	PVOID BaseAddress;
	ULONG AllocationAttributes;
	LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;

// symbols
typedef struct _SECTION_IMAGE_INFORMATION
{
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	union
	{
		struct
		{
			USHORT MajorOperatingSystemVersion;
			USHORT MinorOperatingSystemVersion;
		};
		ULONG OperatingSystemVersion;
	};
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR ComPlusPrefer32bit : 1;
			UCHAR Reserved : 2;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

// symbols
typedef struct _SECTION_INTERNAL_IMAGE_INFORMATION
{
	SECTION_IMAGE_INFORMATION SectionInformation;
	union
	{
		ULONG ExtendedFlags;
		struct
		{
			ULONG ImageExportSuppressionEnabled : 1;
			ULONG ImageCetShadowStacksReady : 1; // 20H1
			ULONG ImageXfgEnabled : 1; // 20H2
			ULONG ImageCetShadowStacksStrictMode : 1;
			ULONG ImageCetSetContextIpValidationRelaxedMode : 1;
			ULONG ImageCetDynamicApisAllowInProc : 1;
			ULONG ImageCetDowngradeReserved1 : 1;
			ULONG ImageCetDowngradeReserved2 : 1;
			ULONG Reserved : 24;
		};
	};
} SECTION_INTERNAL_IMAGE_INFORMATION, * PSECTION_INTERNAL_IMAGE_INFORMATION;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove,
	ApphelpCacheServiceUpdate,
	ApphelpCacheServiceClear,//ApphelpCacheServiceFlush
	ApphelpCacheServiceSnapStatistics,
	ApphelpCacheServiceSnapCache,//5
	ApphelpCacheServiceLookupCdb,//6
	ApphelpCacheServiceRefreshCdb,
	ApphelpCacheServiceMapQuirks,
	ApphelpCacheServiceInvaild,//9 ApphelpCacheServiceHwIdQuery
	ApphelpCacheServiceInitProcessData,// 10 = 0xA, PPL Process WinTcb PackageProcess
	ApphelpCacheServiceLookupAndWriteToProcess,// 11
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, * PAPPHELPCACHESERVICECLASS;

  //	AhcInfoClassSdbQueryResult          = 0x00000001,
  //	AhcInfoClassSdbSxsOverrideManifest  = 0x00000002,
  //	AhcInfoClassSdbRunlevelFlags        = 0x00000004,
  //	AhcInfoClassSdbFusionFlags          = 0x00000008,
  //	AhcInfoClassSdbInstallerFlags       = 0x00000010,
  // 
  //	AhcServiceData.Lookup.InfoClass = 0x1F [CompatCacheLookupAndWriteToProcess]
/*
typedef enum _AHC_SERVICE_CLASS {
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove,
	ApphelpCacheServiceUpdate,
	ApphelpCacheServiceClear,
	ApphelpCacheServiceSnapStatistics,
	ApphelpCacheServiceSnapCache,
	ApphelpCacheServiceLookupCdb,
	ApphelpCacheServiceRefreshCdb,
	ApphelpCacheServiceMapQuirks,
	ApphelpCacheServiceHwIdQuery,//0x9
	ApphelpCacheServiceMax
} AHC_SERVICE_CLASS;
*/

typedef enum _APPHELPCOMMAND
{
	AppHelpCahceLookup = 0,                //  IoControlCode: 0x220003*
	AppHelpCahceRemove,                //  IoControlCode:  0x220007*
	AppHelpCahceUpdate,                //  IoControlCode:  0x22000B*
	AppHelpCacheFlush,               //  IoControlCode: 0x22000F* 
	AppHelpCacheDump,                  //  IoControlCode: 0x220013 
	AppHelpCacheNotifyStart,          //  IoControlCode: 0x220017 
	AppHelpCacheNotifyStop,            //  IoControlCode: 0x22001B
	AppHelpCahceForward,               //  IoControlCode:  0x22001F
	AppHelpCacheQuery,                 //  IoControlCode: 0x220023
	AppHelpQueryModule,                //  IoControlCode: 0x220027
	AppHelpRefresh,                    //  IoControlCode: 0x22002B
	AppHelpCheckForChange,             //  IoControlCode: 0x22002F
	AppHelpQueryHwId                   //11 = 0xB
} APPHELPCOMMAND;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
	ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
	ObjectNameInformation, // q: OBJECT_NAME_INFORMATION
	ObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;
typedef struct _FILE_ID_INFORMATION
{
	ULONGLONG VolumeSerialNumber;//0
	FILE_ID_128 FileId;//8 GUID -> 16
} FILE_ID_INFORMATION, * PFILE_ID_INFORMATION;//24

// private
typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID KeyContext;
	PVOID ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1, // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileFullDirectoryInformation, // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileBothDirectoryInformation, // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileBasicInformation, // q; s: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
	FileStandardInformation, // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
	FileInternalInformation, // q: FILE_INTERNAL_INFORMATION
	FileEaInformation, // q: FILE_EA_INFORMATION
	FileAccessInformation, // q: FILE_ACCESS_INFORMATION
	FileNameInformation, // q: FILE_NAME_INFORMATION
	FileRenameInformation, // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
	FileLinkInformation, // s: FILE_LINK_INFORMATION
	FileNamesInformation, // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileDispositionInformation, // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
	FilePositionInformation, // q; s: FILE_POSITION_INFORMATION
	FileFullEaInformation, // FILE_FULL_EA_INFORMATION
	FileModeInformation, // q; s: FILE_MODE_INFORMATION
	FileAlignmentInformation, // q: FILE_ALIGNMENT_INFORMATION
	FileAllInformation, // q: FILE_ALL_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileAllocationInformation, // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
	FileEndOfFileInformation, // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
	FileAlternateNameInformation, // q: FILE_NAME_INFORMATION
	FileStreamInformation, // q: FILE_STREAM_INFORMATION
	FilePipeInformation, // q; s: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
	FilePipeLocalInformation, // q: FILE_PIPE_LOCAL_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FilePipeRemoteInformation, // q; s: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
	FileMailslotQueryInformation, // q: FILE_MAILSLOT_QUERY_INFORMATION
	FileMailslotSetInformation, // s: FILE_MAILSLOT_SET_INFORMATION
	FileCompressionInformation, // q: FILE_COMPRESSION_INFORMATION
	FileObjectIdInformation, // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileCompletionInformation, // s: FILE_COMPLETION_INFORMATION // 30
	FileMoveClusterInformation, // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
	FileQuotaInformation, // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileReparsePointInformation, // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileNetworkOpenInformation, // q: FILE_NETWORK_OPEN_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileAttributeTagInformation, // q: FILE_ATTRIBUTE_TAG_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileTrackingInformation, // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
	FileIdBothDirectoryInformation, // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileIdFullDirectoryInformation, // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
	FileValidDataLengthInformation, // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
	FileShortNameInformation, // s: FILE_NAME_INFORMATION (requires DELETE) // 40
	FileIoCompletionNotificationInformation, // q; s: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES) // since VISTA
	FileIoStatusBlockRangeInformation, // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
	FileIoPriorityHintInformation, // q; s: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
	FileSfioReserveInformation, // q; s: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
	FileSfioVolumeInformation, // q: FILE_SFIO_VOLUME_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileHardLinkInformation, // q: FILE_LINKS_INFORMATION
	FileProcessIdsUsingFileInformation, // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileNormalizedNameInformation, // q: FILE_NAME_INFORMATION
	FileNetworkPhysicalNameInformation, // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
	FileIdGlobalTxDirectoryInformation, // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
	FileIsRemoteDeviceInformation, // q: FILE_IS_REMOTE_DEVICE_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileUnusedInformation,
	FileNumaNodeInformation, // q: FILE_NUMA_NODE_INFORMATION
	FileStandardLinkInformation, // q: FILE_STANDARD_LINK_INFORMATION
	FileRemoteProtocolInformation, // q: FILE_REMOTE_PROTOCOL_INFORMATION
	FileRenameInformationBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION // since WIN8
	FileLinkInformationBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION
	FileVolumeNameInformation, // q: FILE_VOLUME_NAME_INFORMATION
	FileIdInformation, // q: FILE_ID_INFORMATION
	FileIdExtdDirectoryInformation, // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
	FileReplaceCompletionInformation, // s: FILE_COMPLETION_INFORMATION // since WINBLUE
	FileHardLinkFullIdInformation, // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
	FileIdExtdBothDirectoryInformation, // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
	FileDispositionInformationEx, // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
	FileRenameInformationEx, // s: FILE_RENAME_INFORMATION_EX
	FileRenameInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION_EX
	FileDesiredStorageClassInformation, // q; s: FILE_DESIRED_STORAGE_CLASS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since REDSTONE2
	FileStatInformation, // q: FILE_STAT_INFORMATION (requires FILE_READ_ATTRIBUTES)
	FileMemoryPartitionInformation, // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
	FileStatLxInformation, // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
	FileCaseSensitiveInformation, // q; s: FILE_CASE_SENSITIVE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
	FileLinkInformationEx, // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
	FileLinkInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION_EX
	FileStorageReserveIdInformation, // q; s: FILE_STORAGE_RESERVE_ID_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
	FileCaseSensitiveInformationForceAccessCheck, // q; s: FILE_CASE_SENSITIVE_INFORMATION
	FileKnownFolderInformation, // q; s: FILE_KNOWN_FOLDER_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since WIN11
	FileStatBasicInformation, // since 23H2
	FileId64ExtdDirectoryInformation,
	FileId64ExtdBothDirectoryInformation,
	FileIdAllExtdDirectoryInformation,
	FileIdAllExtdBothDirectoryInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, * PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, * PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, * PKCONTINUE_ARGUMENT;


typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone,
	PsProtectedTypeProtectedLight,
	PsProtectedTypeProtected,
	PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

#define PS_PROTECTED_SIGNER_MASK 0xFF
#define PS_PROTECTED_AUDIT_MASK 0x08
#define PS_PROTECTED_TYPE_MASK 0x07

// vProtectionLevel.Level = PsProtectedValue(PsProtectedSignerCodeGen, FALSE, PsProtectedTypeProtectedLight)
#define PsProtectedValue(aSigner, aAudit, aType) ( \
    ((aSigner & PS_PROTECTED_SIGNER_MASK) << 4) | \
    ((aAudit & PS_PROTECTED_AUDIT_MASK) << 3) | \
    (aType & PS_PROTECTED_TYPE_MASK)\
    )

// InitializePsProtection(&vProtectionLevel, PsProtectedSignerCodeGen, FALSE, PsProtectedTypeProtectedLight)
#define InitializePsProtection(aProtectionLevelPtr, aSigner, aAudit, aType) { \
    (aProtectionLevelPtr)->Signer = aSigner; \
    (aProtectionLevelPtr)->Audit = aAudit; \
    (aProtectionLevelPtr)->Type = aType; \
    }

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // qs: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement 
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets, // 80
	ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection, // q: HANDLE
	ProcessDebugAuthInformation, // since REDSTONE4 // 90
	ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since REDSTONE5
	ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
	ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange, // since WIN11
	ProcessApplyStateChange,
	ProcessEnableOptionalXStateFeatures,
	ProcessAltPrefetchParam, // since 22H1
	ProcessAssignCpuPartitions,
	ProcessPriorityClassEx,
	ProcessMembershipInformation,
	ProcessEffectiveIoPriority,
	ProcessEffectivePagePriority,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;

	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName; // REDSTONE4
	UNICODE_STRING HeapPartitionName; // 19H1
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
	ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _CURDIR32
{
	UNICODE_STRING32 DosPath;
	WOW64_POINTER(HANDLE) Handle;
} CURDIR32, * PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, * PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	WOW64_POINTER(HANDLE) ConsoleHandle;
	ULONG ConsoleFlags;
	WOW64_POINTER(HANDLE) StandardInput;
	WOW64_POINTER(HANDLE) StandardOutput;
	WOW64_POINTER(HANDLE) StandardError;

	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	WOW64_POINTER(PVOID) Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING32 WindowTitle;
	UNICODE_STRING32 DesktopInfo;
	UNICODE_STRING32 ShellInfo;
	UNICODE_STRING32 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	WOW64_POINTER(ULONG_PTR) EnvironmentSize;
	WOW64_POINTER(ULONG_PTR) EnvironmentVersion;
	WOW64_POINTER(PVOID) PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING32 RedirectionDllName; // REDSTONE4
	UNICODE_STRING32 HeapPartitionName; // 19H1
	WOW64_POINTER(ULONG_PTR) DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
	ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;

//
//https://github.com/diversenok/NtUtilsLibrary
//
//#define RTL_USER_PROC_VAILD_CREATE_CAPTURE_MASK 0xBFEF1EE
// 0x8FEF1EE
// 0xBFEF1EE

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_USER_PROC_PROFILE_USER 0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008
#define RTL_USER_PROC_RESERVE_1MB 0x00000020
#define RTL_USER_PROC_RESERVE_16MB 0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100

#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000
#define RTL_USER_PROC_DEV_OVERRIDE_ENABLED 0x00008000//#define RTL_USER_PROC_USE_DOTLOCAL 0x00008000

#define RTL_USER_PROC_OPTIN_PROCESS						0x00020000
#define RTL_USER_PROC_SESSION_OWNER						0x00040000
#define RTL_USER_PROC_HANDLE_USER_CALLBACK_EXCEPTIONS	0x00080000

#define RTL_USER_PROC_PROTECTED_PROCESS					0x00400000

// win 11 Insider newer!
// 0x01000000
#define RTL_USER_PROC_NO_IMAGE_EXPANSION_MITIGATION 0x02000000
#define RTL_USER_PROC_APPX_LOADER_ALTERNATE_FORWARDER 0x04000000 //win 11 LdrpInitializePolicy AppModelPolicy_LoaderIncludeAlternateForwarders_True = 0x360001, // xxx unable set in nt!NtCreateUserProcess?
//
#define RTL_USER_PROC_APPX_GLOBAL_OVERRIDE 0x08000000 //uncorrected

// xxx
#define RTL_USER_PROC_LOADER_FORWARDER 0x20000000 // win 11 L"forwarder\\alt" when LoaderIncludeAlternateForwarders else L"forwarder"
#define RTL_USER_PROC_EXIT_PROCESS_NORMAL 0x40000000 // LdrShutdownProcess uncorrected
#define RTL_USER_PROC_SECURE_PROCESS 0x80000000



// private
#define PROTECTION_LEVEL_WINTCB_LIGHT 0x00000000
#define PROTECTION_LEVEL_WINDOWS 0x00000001
#define PROTECTION_LEVEL_WINDOWS_LIGHT 0x00000002
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT 0x00000003
#define PROTECTION_LEVEL_LSA_LIGHT 0x00000004
#define PROTECTION_LEVEL_WINTCB 0x00000005
#define PROTECTION_LEVEL_CODEGEN_LIGHT 0x00000006
#define PROTECTION_LEVEL_AUTHENTICODE 0x00000007

typedef struct _TOKEN_ORIGIN_CLAIM {
	ULONG Flags;
	WCHAR ImageFileName[MAX_PATH];
} TOKEN_ORIGIN_CLAIM;

// private
typedef enum _SE_SAFE_OPEN_PROMPT_EXPERIENCE_RESULTS {
	SeSafeOpenExperienceNone = 0x00,
	SeSafeOpenExperienceCalled = 0x01,
	SeSafeOpenExperienceAppRepCalled = 0x02,
	SeSafeOpenExperiencePromptDisplayed = 0x04,
	SeSafeOpenExperienceUAC = 0x08,
	SeSafeOpenExperienceUninstaller = 0x10,
	SeSafeOpenExperienceIgnoreUnknownOrBad = 0x20,
	SeSafeOpenExperienceDefenderTrustedInstaller = 0x40,
	SeSafeOpenExperienceMOTWPresent = 0x80
} SE_SAFE_OPEN_PROMPT_EXPERIENCE_RESULTS;

// private
typedef struct _SE_SAFE_OPEN_PROMPT_RESULTS {
	SE_SAFE_OPEN_PROMPT_EXPERIENCE_RESULTS Results;
	WCHAR Path[MAX_PATH];
} SE_SAFE_OPEN_PROMPT_RESULTS, * PSE_SAFE_OPEN_PROMPT_RESULTS;

#define BNOISOLATION_PREFIX_MAXLENGTH 136
typedef struct _PROC_THREAD_BNOISOLATION_ATTRIBUTE
{
	BOOL IsolationEnabled;
	WCHAR IsolationPrefix[BNOISOLATION_PREFIX_MAXLENGTH];
} PROC_THREAD_BNOISOLATION_ATTRIBUTE, * PPROC_THREAD_BNOISOLATION_ATTRIBUTE;

// private
typedef struct _ISOLATION_MANIFEST_PROPERTIES {
	UNICODE_STRING InstancePath;
	UNICODE_STRING FriendlyName;
	UNICODE_STRING Description;
	ULONG_PTR Level;
} ISOLATION_MANIFEST_PROPERTIES, * PISOLATION_MANIFEST_PROPERTIES;

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess, // in HANDLE
	PsAttributeDebugObject, // in HANDLE
	PsAttributeToken, // in HANDLE
	PsAttributeClientId, // out PCLIENT_ID
	PsAttributeTebAddress, // out PTEB *
	PsAttributeImageName, // in PWSTR
	PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass, // in UCHAR
	PsAttributeErrorMode, // in ULONG
	PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
	PsAttributeHandleList, // in HANDLE[]
	PsAttributeGroupAffinity, // in PGROUP_AFFINITY
	PsAttributePreferredNode, // in PUSHORT
	PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
	PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
	PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE

	// v57 = *(_QWORD*)&Attributes->Size;
	// if (v57 && (v57 & 7) == 0 && v57 <= 0x88)// 8 的整数倍
	// {
	//	...nt!IsTrustletCreateAttributeWellFormed(*(_QWORD *)(OutProcessContext + 352), TrustletSize);
	// }
	// .rdata:000000014000C418                                         ; DATA XREF: IsTrustletCreateAttributeWellFormed+6E↓o
	// .rdata:000000014000C420                 dq offset TrustletType_CollaborationId
	// .rdata : 000000014000C428                 dq offset TrustletType_VmId
	// .rdata : 000000014000C430                 dq offset TrustletType_TkSessionId
	// .rdata : 000000014000C438                 dq offset TrustletType_TrustedApp
	//
	PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD  (size: 8 or 24) 
	PsAttributeJobList, // in HANDLE[]
	PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) nt!SepSetTokenAllApplicationPackagesPolicy // since REDSTONE 
	PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
	PsAttributeSafeOpenPromptOriginClaim, // in
	PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
	PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
	PsAttributeChpe, // in BOOLEAN // since REDSTONE3
	PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
	PsAttributeMachineType, // in WORD // since 21H2
	PsAttributeComponentFilter,
	PsAttributeEnableOptionalXStateFeatures, // since WIN11
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

// begin_rev
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // can be used with threads
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 /// Is an additional option (see ProcThreadAttributeValue in WinBase.h
// end_rev

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)

typedef struct _PS_ATTRIBUTE {
	ULONGLONG Attribute;				/// PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
	SIZE_T Size;						/// Size of Value or *ValuePtr
	union {
		ULONG_PTR Value;				/// Reserve 8 bytes for data (such as a Handle or a data pointer)
		PVOID ValuePtr;					/// data pointer
	};
	PSIZE_T ReturnLength;				/// Either 0 or specifies size of data returned to caller via "ValuePtr"
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;					/// sizeof(PS_ATTRIBUTE_LIST)
	PS_ATTRIBUTE Attributes[32];			/// Depends on how many attribute entries should be supplied to NtCreateUserProcess
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _PS_MEMORY_RESERVE {
	PVOID ReserveAddress;
	SIZE_T ReserveSize;
} PS_MEMORY_RESERVE, * PPS_MEMORY_RESERVE;

typedef enum _PS_STD_HANDLE_STATE {
	PsNeverDuplicate,
	PsRequestDuplicate, // duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
	PsAlwaysDuplicate, // always duplicate standard handles
	PsMaxStdHandleStates
} PS_STD_HANDLE_STATE;

// begin_rev
#define PS_STD_INPUT_HANDLE 0x1
#define PS_STD_OUTPUT_HANDLE 0x2
#define PS_STD_ERROR_HANDLE 0x4
// end_rev
#define PS_STD_HANDLE_MASK_FLAG
typedef struct _PS_STD_HANDLE_INFO {
	union {
		ULONG Flags; //0x121 = 100100001
		struct {
			ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
			ULONG PseudoHandleMask : 3; // PS_STD_*
		};
	};
	ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;

typedef union _PS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS
{
	UCHAR Trustlet : 1;
	UCHAR Ntos : 1;
	UCHAR WriteHandle : 1;
	UCHAR ReadHandle : 1;
	UCHAR Reserved : 4;
	UCHAR AccessRights;
} PS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS, * PPS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS;

// 00 02 11 00			TrustletType_CollaborationId	0x00110200
// 00 02 13 03			TrustletType_VmId				0x03130200
// 00 01 14 00          TrustletType_TrustedApp			0x00140100
// 00 04 12 00          TrustletType_TkSessionId		0x00120400
typedef struct _PS_TRUSTLET_ATTRIBUTE_TYPE
{
	union
	{
		struct
		{
			UCHAR Version;
			UCHAR DataCount;
			UCHAR SemanticType;
			PS_TRUSTLET_ATTRIBUTE_ACCESSRIGHTS AccessRights;
		};
		ULONG AttributeType;
	};
} PS_TRUSTLET_ATTRIBUTE_TYPE, * PPS_TRUSTLET_ATTRIBUTE_TYPE;

typedef struct _PS_TRUSTLET_ATTRIBUTE_HEADER
{
	PS_TRUSTLET_ATTRIBUTE_TYPE AttributeType;
	ULONG InstanceNumber : 8;
	ULONG Reserved : 24;
} PS_TRUSTLET_ATTRIBUTE_HEADER, * PPS_TRUSTLET_ATTRIBUTE_HEADER;

typedef struct _PS_TRUSTLET_ATTRIBUTE_DATA
{
	PS_TRUSTLET_ATTRIBUTE_HEADER Header;
	ULONGLONG Data[1];
} PS_TRUSTLET_ATTRIBUTE_DATA, * PPS_TRUSTLET_ATTRIBUTE_DATA;

typedef struct _PS_TRUSTLET_CREATE_ATTRIBUTES
{
	ULONGLONG TrustletIdentity;
	PS_TRUSTLET_ATTRIBUTE_DATA Attributes[1];
} PS_TRUSTLET_CREATE_ATTRIBUTES, * PPS_TRUSTLET_CREATE_ATTRIBUTES;

// private
typedef struct _PS_BNO_ISOLATION_PARAMETERS
{
	UNICODE_STRING IsolationPrefix;
	ULONG HandleCount;
	PVOID* Handles;
	BOOLEAN IsolationEnabled;
} PS_BNO_ISOLATION_PARAMETERS, * PPS_BNO_ISOLATION_PARAMETERS;

// windows-internals-book:"Chapter 5" 
typedef enum _PS_CREATE_STATE {
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,//6
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
	SIZE_T Size;//0x0
	PS_CREATE_STATE State;//0x08
	union {//0x10
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;//0x10 value = 0x8
				struct {
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative; //40
			ULONG UserProcessParametersWow64;//44
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;
typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;
typedef struct _ACTIVATION_CONTEXT_STACK
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

// private
typedef struct _API_SET_NAMESPACE
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

// private
typedef struct _API_SET_HASH_ENTRY
{
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY, * PAPI_SET_HASH_ENTRY;

// private
typedef struct _API_SET_NAMESPACE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;

// private
typedef struct _API_SET_VALUE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;

typedef struct _TELEMETRY_COVERAGE_HEADER
{
	UCHAR MajorVersion;
	UCHAR MinorVersion;
	struct
	{
		USHORT TracingEnabled : 1;
		USHORT Reserved1 : 15;
	};
	ULONG HashTableEntries;
	ULONG HashIndexMask;
	ULONG TableUpdateVersion;
	ULONG TableSizeInBytes;
	ULONG LastResetTick;
	ULONG ResetRound;
	ULONG Reserved2;
	ULONG RecordedCount;
	ULONG Reserved3[4];
	ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, * PTELEMETRY_COVERAGE_HEADER;
typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
	ULONG Flags;
	UNICODE_STRING DosPath;
	HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

#define ASSEMBLY_STORAGE_MAP_ASSEMBLY_ARRAY_IS_HEAP_ALLOCATED 0x00000001

typedef struct _ASSEMBLY_STORAGE_MAP
{
	ULONG Flags;
	ULONG AssemblyCount;
	PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

typedef struct _SILO_USER_SHARED_DATA* PSILO_USER_SHARED_DATA;
typedef struct _LEAP_SECOND_DATA* PLEAP_SECOND_DATA;

#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG_PTR HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
	_In_ PVOID DllHandle,
	_In_ ULONG Reason,
	_In_opt_ PVOID Context
	);

// symbols
typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

// symbols
typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

// symbols
typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

// symbols
typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union
	{
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

// rev
typedef struct _LDR_DEPENDENCY_RECORD
{
	SINGLE_LIST_ENTRY DependencyLink;
	PLDR_DDAG_NODE DependencyNode;
	SINGLE_LIST_ENTRY IncomingDependencyLink;
	PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, * PLDR_DEPENDENCY_RECORD;

// symbols
typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary, // since REDSTONE3
	LoadReasonEnclaveDependency,
	LoadReasonPatchImage, // since WIN11
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage,
	LdrHotPatchNotApplied,
	LdrHotPatchAppliedReserve,
	LdrHotPatchAppliedForward,
	LdrHotPatchFailedToPatch,
	LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

// symbols
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PLDR_INIT_ROUTINE EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ChpeEmulatorImage : 1;
			ULONG ReservedFlags5 : 1;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock; // RtlAcquireSRWLockExclusive
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason; // since WIN8
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount; // since WIN10
	ULONG DependentLoadFlags;
	UCHAR SigningLevel; // since REDSTONE2
	ULONG CheckSum; // since 22H1
	PVOID ActivePatchImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _ACTIVATION_CONTEXT_DATA {
	ULONG Magic;
	ULONG HeaderSize;
	ULONG FormatVersion;
	ULONG TotalSize;
	ULONG DefaultTocOffset;
	ULONG ExtendedTocOffset;
	ULONG AssemblyRosterOffset;
	ULONG Flags;
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PSLIST_HEADER AtlThunkSListPtr;
	PVOID IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1; // REDSTONE5
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2]; // TLS_MINIMUM_AVAILABLE

	PVOID ReadOnlySharedMemoryBase;
	PSILO_USER_SHARED_DATA SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable; // PGDI_SHARED_MEMORY
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32]; // TLS_EXPANSION_SLOTS

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags; // KACF_*
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;	// APPCOMPAT_EXE_DATA*
	PVOID AppCompatInfo; // APP_COMPAT_INFO*

	UNICODE_STRING CSDVersion;

	PACTIVATION_CONTEXT_DATA ActivationContextData;
	PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
	PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
	PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
	PVOID PatchLoaderData;
	PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

	ULONG AppModelFeatureState;
	ULONG SpareUlongs[2];

	USHORT ActiveCodePage;
	USHORT OemCodePage;
	USHORT UseCaseMapping;
	USHORT UnusedNlsField;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;

	union
	{
		PVOID pContextData; // WIN7
		PVOID pUnused; // WIN10
		PVOID EcCodeBitMap; // WIN11
	};

	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PRTL_CRITICAL_SECTION TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	PLEAP_SECOND_DATA LeapSecondData; // REDSTONE5
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
	ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB, * PPEB;

typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};
	WOW64_POINTER(HANDLE) Mutant;

	WOW64_POINTER(PVOID) ImageBaseAddress;
	WOW64_POINTER(PPEB_LDR_DATA) Ldr;
	WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
	WOW64_POINTER(PVOID) SubSystemData;
	WOW64_POINTER(PVOID) ProcessHeap;
	WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
	WOW64_POINTER(PVOID) AtlThunkSListPtr;
	WOW64_POINTER(PVOID) IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union
	{
		WOW64_POINTER(PVOID) KernelCallbackTable;
		WOW64_POINTER(PVOID) UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	WOW64_POINTER(PVOID) ApiSetMap;
	ULONG TlsExpansionCounter;
	WOW64_POINTER(PVOID) TlsBitmap;
	ULONG TlsBitmapBits[2];
	WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
	WOW64_POINTER(PVOID) HotpatchInformation;
	WOW64_POINTER(PVOID*) ReadOnlyStaticServerData;
	WOW64_POINTER(PVOID) AnsiCodePageData;
	WOW64_POINTER(PVOID) OemCodePageData;
	WOW64_POINTER(PVOID) UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	WOW64_POINTER(SIZE_T) HeapSegmentReserve;
	WOW64_POINTER(SIZE_T) HeapSegmentCommit;
	WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
	WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	WOW64_POINTER(PVOID*) ProcessHeaps;

	WOW64_POINTER(PVOID) GdiSharedHandleTable;
	WOW64_POINTER(PVOID) ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	WOW64_POINTER(ULONG_PTR) ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER32 GdiHandleBuffer;
	WOW64_POINTER(PVOID) PostProcessInitRoutine;

	WOW64_POINTER(PVOID) TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	WOW64_POINTER(PVOID) pShimData;
	WOW64_POINTER(PVOID) AppCompatInfo;

	UNICODE_STRING32 CSDVersion;

	WOW64_POINTER(PACTIVATION_CONTEXT_DATA) ActivationContextData;
	WOW64_POINTER(PVOID) ProcessAssemblyStorageMap;
	WOW64_POINTER(PACTIVATION_CONTEXT_DATA) SystemDefaultActivationContextData;
	WOW64_POINTER(PVOID) SystemAssemblyStorageMap;

	WOW64_POINTER(SIZE_T) MinimumStackCommit;

	WOW64_POINTER(PVOID) SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
	WOW64_POINTER(PVOID) PatchLoaderData;
	WOW64_POINTER(PVOID) ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

	ULONG AppModelFeatureState;
	ULONG SpareUlongs[2];

	USHORT ActiveCodePage;
	USHORT OemCodePage;
	USHORT UseCaseMapping;
	USHORT UnusedNlsField;

	WOW64_POINTER(PVOID) WerRegistrationData;
	WOW64_POINTER(PVOID) WerShipAssertPtr;

	union
	{
		WOW64_POINTER(PVOID) pContextData; // WIN7
		WOW64_POINTER(PVOID) pUnused; // WIN10
		WOW64_POINTER(PVOID) EcCodeBitMap; // WIN11
	};

	WOW64_POINTER(PVOID) pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	WOW64_POINTER(PVOID) TppWorkerpListLock;
	LIST_ENTRY32 TppWorkerpList;
	WOW64_POINTER(PVOID) WaitOnAddressHashTable[128];
	WOW64_POINTER(PVOID) TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	WOW64_POINTER(PLEAP_SECOND_DATA) LeapSecondData; // REDSTONE5
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
	ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB32, * PPEB32;

typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
	PVOID SystemReserved1[30];
#else
	PVOID SystemReserved1[26];
#endif
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderReserved[11];
	ULONG ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK ActivationStack;

	UCHAR WorkingOnBehalfTicket[8];
	NTSTATUS ExceptionCode;

	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	ULONG_PTR InstrumentationCallbackSp;
	ULONG_PTR InstrumentationCallbackPreviousPc;
	ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
	ULONG TxFsContext;
#endif
	BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
	UCHAR SpareBytes[23];
	ULONG TxFsContext;
#endif
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID PerflibData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		} s1;
	} u1;

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR ReservedForCodeCoverage;
	PVOID ThreadPoolData;
	PVOID* TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	USHORT HeapVirtualAffinity;
	USHORT LowFragHeapDataSlot;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	} u2;
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT LoadOwner : 1;
			USHORT LoaderWorker : 1;
			USHORT SkipLoaderInit : 1;
			USHORT SpareSameTebBits : 1;
		} s2;
	} u3;

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	LONG WowTebOffset;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
	ULONGLONG ReservedForCrt;
	GUID EffectiveContainerId;
	ULONGLONG LastSleepCounter; // Win11
	ULONG SpinCallCount;
	ULONGLONG ExtendedFeatureDisableMask;
} TEB, * PTEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	KAFFINITY AffinityMask;//  ULONG_PTR
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
	ThreadBasePriority, // s: KPRIORITY
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
	ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress, // s: ULONG_PTR 
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // q: BOOLEAN; s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // q: ULONG
	ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context, // qs: WOW64_CONTEXT
	ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
	ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
	ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
	ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
	ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
	ThreadSuspendCount, // q: ULONG // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
	ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
	ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
	ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
	ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
	ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
	ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	ThreadCreateStateChange, // since WIN11
	ThreadApplyStateChange,
	ThreadStrongerBadHandleChecks, // since 22H1
	ThreadEffectiveIoPriority,
	ThreadEffectivePagePriority,
	MaxThreadInfoClass
} THREADINFOCLASS;
/*
typedef enum _TOKEN_INFORMATION_CLASS
{
	TokenUser = 1, // q: TOKEN_USER
	TokenGroups, // q: TOKEN_GROUPS
	TokenPrivileges, // q: TOKEN_PRIVILEGES
	TokenOwner, // q; s: TOKEN_OWNER
	TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
	TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
	TokenSource, // q: TOKEN_SOURCE
	TokenType, // q: TOKEN_TYPE
	TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
	TokenStatistics, // q: TOKEN_STATISTICS // 10
	TokenRestrictedSids, // q: TOKEN_GROUPS
	TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
	TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
	TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
	TokenSandBoxInert, // q: ULONG
	TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
	TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
	TokenElevationType, // q: TOKEN_ELEVATION_TYPE
	TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
	TokenElevation, // q: TOKEN_ELEVATION // 20
	TokenHasRestrictions, // q: ULONG
	TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
	TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
	TokenVirtualizationEnabled, // q; s: ULONG
	TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
	TokenUIAccess, // q; s: ULONG
	TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
	TokenLogonSid, // q: TOKEN_GROUPS
	TokenIsAppContainer, // q: ULONG
	TokenCapabilities, // q: TOKEN_GROUPS // 30
	TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
	TokenAppContainerNumber, // q: ULONG
	TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
	TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
	TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
	TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
	TokenDeviceGroups, // q: TOKEN_GROUPS
	TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
	TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION
	TokenIsRestricted, // q: ULONG // 40
	TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL
	TokenPrivateNameSpace, // q; s: ULONG
	TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION
	TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION
	TokenChildProcessFlags, // s: ULONG
	TokenIsLessPrivilegedAppContainer, // q: ULONG
	TokenIsSandboxed, // q: ULONG
	TokenIsAppSilo, // TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
	MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, * PTOKEN_INFORMATION_CLASS;
*/
typedef enum _APPCONTAINER_SID_TYPE
{
	NotAppContainerSidType,
	ChildAppContainerSidType,
	ParentAppContainerSidType,
	InvalidAppContainerSidType,
	MaxAppContainerSidType
} APPCONTAINER_SID_TYPE, * PAPPCONTAINER_SID_TYPE;
// onecore\internal\minwin\priv_sdk\inc\AppModelPolicy.h
typedef enum _AppModelPolicy_Type
{
	AppModelPolicy_Type_LifecycleManager = 1,
	AppModelPolicy_Type_AppDataAccess = 2,
	AppModelPolicy_Type_WindowingModel = 3,
	AppModelPolicy_Type_DllSearchOrder = 4,
	AppModelPolicy_Type_Fusion = 5,
	AppModelPolicy_Type_NonWindowsCodecLoading = 6,
	AppModelPolicy_Type_ProcessEnd = 7,
	AppModelPolicy_Type_BeginThreadInit = 8,
	AppModelPolicy_Type_DeveloperInformation = 9,
	AppModelPolicy_Type_CreateFileAccess = 10,
	AppModelPolicy_Type_ImplicitPackageBreakaway_Internal = 11,
	AppModelPolicy_Type_ProcessActivationShim = 12,
	AppModelPolicy_Type_AppKnownToStateRepository = 13,
	AppModelPolicy_Type_AudioManagement = 14,
	AppModelPolicy_Type_PackageMayContainPublicComRegistrations = 15,
	AppModelPolicy_Type_PackageMayContainPrivateComRegistrations = 16,
	AppModelPolicy_Type_LaunchCreateProcessExtensions = 17,
	AppModelPolicy_Type_ClrCompat = 18,
	AppModelPolicy_Type_LoaderIgnoreAlteredSearchForRelativePath = 19,
	AppModelPolicy_Type_ImplicitlyActivateClassicAAAServersAsIU = 20,
	AppModelPolicy_Type_ComClassicCatalog = 21,
	AppModelPolicy_Type_ComUnmarshaling = 22,
	AppModelPolicy_Type_ComAppLaunchPerfEnhancements = 23,
	AppModelPolicy_Type_ComSecurityInitialization = 24,
	AppModelPolicy_Type_RoInitializeSingleThreadedBehavior = 25,
	AppModelPolicy_Type_ComDefaultExceptionHandling = 26,
	AppModelPolicy_Type_ComOopProxyAgility = 27,
	AppModelPolicy_Type_AppServiceLifetime = 28,
	AppModelPolicy_Type_WebPlatform = 29,
	AppModelPolicy_Type_WinInetStoragePartitioning = 30,
	AppModelPolicy_Type_IndexerProtocolHandlerHost = 31, // since Win RS2
	AppModelPolicy_Type_LoaderIncludeUserDirectories = 32,
	AppModelPolicy_Type_ConvertAppContainerToRestrictedAppContainer = 33,
	AppModelPolicy_Type_PackageMayContainPrivateMapiProvider = 34,
	AppModelPolicy_Type_AdminProcessPackageClaims = 35, // since Win RS3
	AppModelPolicy_Type_RegistryRedirectionBehavior = 36,
	AppModelPolicy_Type_BypassCreateProcessAppxExtension = 37,
	AppModelPolicy_Type_KnownFolderRedirection = 38,
	AppModelPolicy_Type_PrivateActivateAsPackageWinrtClasses = 39,
	AppModelPolicy_Type_AppPrivateFolderRedirection = 40,
	AppModelPolicy_Type_GlobalSystemAppDataAccess = 41,
	AppModelPolicy_Type_ConsoleHandleInheritance = 42, // since Win RS4
	AppModelPolicy_Type_ConsoleBufferAccess = 43,
	AppModelPolicy_Type_ConvertCallerTokenToUserTokenForDeployment = 44,
	AppModelPolicy_Type_ShellExecuteRetrieveIdentityFromCurrentProcess = 45, // since Win RS5
	AppModelPolicy_Type_CodeIntegritySigning = 46, // since Win 19H1
	AppModelPolicy_Type_PTCActivation = 47,
	AppModelPolicy_Type_ComIntraPackageRpcCall = 48, // since Win 20H1
	AppModelPolicy_Type_LoadUser32ShimOnWindowsCoreOS = 49,
	AppModelPolicy_Type_SecurityCapabilitiesOverride = 50,
	AppModelPolicy_Type_CurrentDirectoryOverride = 51,
	AppModelPolicy_Type_ComTokenMatchingForAAAServers = 52,
	AppModelPolicy_Type_UseOriginalFileNameInTokenFQBNAttribute = 53,
	AppModelPolicy_Type_LoaderIncludeAlternateForwarders = 54,
	AppModelPolicy_Type_PullPackageDependencyData = 55,
	AppModelPolicy_Type_AppInstancingErrorBehavior = 56, // since Win 11
	AppModelPolicy_Type_BackgroundTaskRegistrationType = 57,
	AppModelPolicy_Type_ModsPowerNotification = 58,
	AppModelPolicy_Type_Count = 58,
} AppModelPolicy_Type;

typedef enum _AppModelPolicy_PolicyValue
{
	AppModelPolicy_LifecycleManager_Unmanaged = 0x10000,												//Win 10 RS1+
	AppModelPolicy_LifecycleManager_ManagedByPLM = 0x10001,
	AppModelPolicy_LifecycleManager_ManagedByEM = 0x10002,
	AppModelPolicy_AppDataAccess_Allowed = 0x20000,
	AppModelPolicy_AppDataAccess_Denied = 0x20001,
	AppModelPolicy_WindowingModel_Hwnd = 0x30000,
	AppModelPolicy_WindowingModel_CoreWindow = 0x30001,
	AppModelPolicy_WindowingModel_LegacyPhone = 0x30002,
	AppModelPolicy_WindowingModel_None = 0x30003,
	AppModelPolicy_DllSearchOrder_Traditional = 0x40000,
	AppModelPolicy_DllSearchOrder_PackageGraphBased = 0x40001,
	AppModelPolicy_Fusion_Full = 0x50000,
	AppModelPolicy_Fusion_Limited = 0x50001,
	AppModelPolicy_NonWindowsCodecLoading_Allowed = 0x60000,
	AppModelPolicy_NonWindowsCodecLoading_Denied = 0x60001,
	AppModelPolicy_ProcessEnd_TerminateProcess = 0x70000,
	AppModelPolicy_ProcessEnd_ExitProcess = 0x70001,
	AppModelPolicy_BeginThreadInit_RoInitialize = 0x80000,
	AppModelPolicy_BeginThreadInit_None = 0x80001,
	AppModelPolicy_DeveloperInformation_UI = 0x90000,
	AppModelPolicy_DeveloperInformation_None = 0x90001,
	AppModelPolicy_CreateFileAccess_Full = 0xa0000,
	AppModelPolicy_CreateFileAccess_Limited = 0xa0001,
	AppModelPolicy_ImplicitPackageBreakaway_Allowed = 0xb0000,
	AppModelPolicy_ImplicitPackageBreakaway_Denied = 0xb0001,
	AppModelPolicy_ImplicitPackageBreakaway_DeniedByApp = 0xb0002,
	AppModelPolicy_ProcessActivationShim_None = 0xc0000,
	AppModelPolicy_ProcessActivationShim_PackagedCWALauncher = 0xc0001,
	AppModelPolicy_AppKnownToStateRepository_Known = 0xd0000,
	AppModelPolicy_AppKnownToStateRepository_Unknown = 0xd0001,
	AppModelPolicy_AudioManagement_Unmanaged = 0xe0000,
	AppModelPolicy_AudioManagement_ManagedByPBM = 0xe0001,
	AppModelPolicy_PackageMayContainPublicComRegistrations_Yes = 0xf0000,
	AppModelPolicy_PackageMayContainPublicComRegistrations_No = 0xf0001,
	AppModelPolicy_PackageMayContainPrivateComRegistrations_None = 0x100000,
	AppModelPolicy_PackageMayContainPrivateComRegistrations_PrivateHive = 0x100001,
	AppModelPolicy_LaunchCreateProcessExtensions_None = 0x110000,
	AppModelPolicy_LaunchCreateProcessExtensions_RegisterWithPsm = 0x110001,
	AppModelPolicy_LaunchCreateProcessExtensions_RegisterWithDesktopAppX = 0x110002,
	AppModelPolicy_LaunchCreateProcessExtensions_RegisterWithDesktopAppXNoHeliumContainer = 0x110003,
	AppModelPolicy_ClrCompat_Others = 0x120000,
	AppModelPolicy_ClrCompat_ClassicDesktop = 0x120001,
	AppModelPolicy_ClrCompat_Universal = 0x120002,
	AppModelPolicy_ClrCompat_PackagedDesktop = 0x120003,
	AppModelPolicy_LoaderIgnoreAlteredSearchForRelativePath_False = 0x130000,
	AppModelPolicy_LoaderIgnoreAlteredSearchForRelativePath_True = 0x130001,
	AppModelPolicy_ImplicitlyActivateClassicAAAServersAsIU_Yes = 0x140000,
	AppModelPolicy_ImplicitlyActivateClassicAAAServersAsIU_No = 0x140001,
	AppModelPolicy_ComClassicCatalog_MachineHiveAndUserHive = 0x150000,
	AppModelPolicy_ComClassicCatalog_MachineHiveOnly = 0x150001,
	AppModelPolicy_ComUnmarshaling_ForceStrongUnmarshaling = 0x160000,
	AppModelPolicy_ComUnmarshaling_ApplicationManaged = 0x160001,
	AppModelPolicy_ComAppLaunchPerfEnhancements_Enabled = 0x170000,
	AppModelPolicy_ComAppLaunchPerfEnhancements_Disabled = 0x170001,
	AppModelPolicy_ComSecurityInitialization_ApplicationManaged = 0x180000,
	AppModelPolicy_ComSecurityInitialization_SystemManaged = 0x180001,
	AppModelPolicy_RoInitializeSingleThreadedBehavior_ASTA = 0x190000,
	AppModelPolicy_RoInitializeSingleThreadedBehavior_STA = 0x190001,
	AppModelPolicy_ComDefaultExceptionHandling_HandleAll = 0x1a0000,
	AppModelPolicy_ComDefaultExceptionHandling_HandleNone = 0x1a0001,
	AppModelPolicy_ComOopProxyAgility_Agile = 0x1b0000,
	AppModelPolicy_ComOopProxyAgility_NonAgile = 0x1b0001,
	AppModelPolicy_AppServiceLifetime_StandardTimeout = 0x1c0000,
	AppModelPolicy_AppServiceLifetime_ExtensibleTimeout = 0x1c0001,
	AppModelPolicy_AppServiceLifetime_ExtendedForSamePackage = 0x1c0002,
	AppModelPolicy_WebPlatform_Edge = 0x1d0000,
	AppModelPolicy_WebPlatform_Legacy = 0x1d0001,
	AppModelPolicy_WinInetStoragePartitioning_Isolated = 0x1e0000,
	AppModelPolicy_WinInetStoragePartitioning_SharedWithAppContainer = 0x1e0001,
	AppModelPolicy_IndexerProtocolHandlerHost_PerUser = 0x1f0000,// Win 10 RS2+
	AppModelPolicy_IndexerProtocolHandlerHost_PerApp = 0x1f0001,
	AppModelPolicy_LoaderIncludeUserDirectories_False = 0x200000,
	AppModelPolicy_LoaderIncludeUserDirectories_True = 0x200001,
	AppModelPolicy_ConvertAppContainerToRestrictedAppContainer_False = 0x210000,
	AppModelPolicy_ConvertAppContainerToRestrictedAppContainer_True = 0x210001,
	AppModelPolicy_PackageMayContainPrivateMapiProvider_None = 0x220000,
	AppModelPolicy_PackageMayContainPrivateMapiProvider_PrivateHive = 0x220001,
	AppModelPolicy_AdminProcessPackageClaims_None = 0x230000,											//Win 10 RS3+
	AppModelPolicy_AdminProcessPackageClaims_Caller = 0x230001,
	AppModelPolicy_RegistryRedirectionBehavior_None = 0x240000,
	AppModelPolicy_RegistryRedirectionBehavior_CopyOnWrite = 0x240001,
	AppModelPolicy_BypassCreateProcessAppxExtension_False = 0x250000,
	AppModelPolicy_BypassCreateProcessAppxExtension_True = 0x250001,
	AppModelPolicy_KnownFolderRedirection_Isolated = 0x260000,
	AppModelPolicy_KnownFolderRedirection_RedirectToPackage = 0x260001,
	AppModelPolicy_PrivateActivateAsPackageWinrtClasses_AllowNone = 0x270000,
	AppModelPolicy_PrivateActivateAsPackageWinrtClasses_AllowFullTrust = 0x270001,
	AppModelPolicy_PrivateActivateAsPackageWinrtClasses_AllowNonFullTrust = 0x270002,
	AppModelPolicy_AppPrivateFolderRedirection_None = 0x280000,
	AppModelPolicy_AppPrivateFolderRedirection_AppPrivate = 0x280001,
	AppModelPolicy_GlobalSystemAppDataAccess_Normal = 0x290000,
	AppModelPolicy_GlobalSystemAppDataAccess_Virtualized = 0x290001,
	AppModelPolicy_ConsoleHandleInheritance_ConsoleOnly = 0x2a0000,										//Win 10 RS4+
	AppModelPolicy_ConsoleHandleInheritance_All = 0x2a0001,
	AppModelPolicy_ConsoleBufferAccess_RestrictedUnidirectional = 0x2b0000,
	AppModelPolicy_ConsoleBufferAccess_Unrestricted = 0x2b0001,
	AppModelPolicy_ConvertCallerTokenToUserTokenForDeployment_UserCallerToken = 0x2c0000,
	AppModelPolicy_ConvertCallerTokenToUserTokenForDeployment_ConvertTokenToUserToken = 0x2c0001,
	AppModelPolicy_ShellExecuteRetrieveIdentityFromCurrentProcess_False = 0x2d0000,						// Win 10 RS5+
	AppModelPolicy_ShellExecuteRetrieveIdentityFromCurrentProcess_True = 0x2d0001,
	AppModelPolicy_CodeIntegritySigning_Default = 0x2e0000,												// Win 10 19H1+
	AppModelPolicy_CodeIntegritySigning_OriginBased = 0x2e0001,
	AppModelPolicy_CodeIntegritySigning_OriginBasedForDev = 0x2e0002,
	AppModelPolicy_PTCActivation_Default = 0x2f0000,
	AppModelPolicy_PTCActivation_AllowActivationInBrokerForMediumILContainer = 0x2f0001,
	AppModelPolicy_Type_ComIntraPackageRpcCall_NoWake = 0x300000,										// Win 10 20H1+
	AppModelPolicy_Type_ComIntraPackageRpcCall_Wake = 0x300001,
	AppModelPolicy_LoadUser32ShimOnWindowsCoreOS_True = 0x310000,
	AppModelPolicy_LoadUser32ShimOnWindowsCoreOS_False = 0x310001,
	AppModelPolicy_SecurityCapabilitiesOverride_None = 0x320000,
	AppModelPolicy_SecurityCapabilitiesOverride_PackageCapabilities = 0x320001,
	AppModelPolicy_CurrentDirectoryOverride_None = 0x330000,
	AppModelPolicy_CurrentDirectoryOverride_PackageInstallDirectory = 0x330001,
	AppModelPolicy_ComTokenMatchingForAAAServers_DontUseNtCompareTokens = 0x340000,
	AppModelPolicy_ComTokenMatchingForAAAServers_UseNtCompareTokens = 0x340001,
	AppModelPolicy_UseOriginalFileNameInTokenFQBNAttribute_False = 0x350000,
	AppModelPolicy_UseOriginalFileNameInTokenFQBNAttribute_True = 0x350001,
	AppModelPolicy_LoaderIncludeAlternateForwarders_False = 0x360000,
	AppModelPolicy_LoaderIncludeAlternateForwarders_True = 0x360001,
	AppModelPolicy_PullPackageDependencyData_False = 0x370000,
	AppModelPolicy_PullPackageDependencyData_True = 0x370001,
	AppModelPolicy_AppInstancingErrorBehavior_SuppressErrors = 0x380000,								// Win 11+
	AppModelPolicy_AppInstancingErrorBehavior_RaiseErrors = 0x380001,
	AppModelPolicy_BackgroundTaskRegistrationType_Unsupported = 0x390000,
	AppModelPolicy_BackgroundTaskRegistrationType_Manifested = 0x390001,
	AppModelPolicy_BackgroundTaskRegistrationType_Win32Clsid = 0x390002,
	AppModelPolicy_Type_ModsPowerNotification_Disabled = 0x3a0000,
	AppModelPolicy_Type_ModsPowerNotification_Enabled = 0x3a0001,
	AppModelPolicy_Type_ModsPowerNotification_QueryDam = 0x3a0002,
} AppModelPolicy_PolicyValue;

#define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION 0x1
#define PSM_ACTIVATION_TOKEN_SHARED_ENTITY 0x2
#define PSM_ACTIVATION_TOKEN_FULL_TRUST 0x4
#define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE 0x8
#define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP 0x10
#define PSM_ACTIVATION_TOKEN_BREAKAWAY_INHIBITED 0x20
#define PSM_ACTIVATION_TOKEN_RUNTIME_BROKER 0x40 // rev
#define PSM_ACTIVATION_TOKEN_UNIVERSAL_CONSOLE 0x200 // rev
#define PSM_ACTIVATION_TOKEN_WIN32ALACARTE_PROCESS 0x10000 // rev

#define PSMP_MINIMUM_SYSAPP_CLAIM_VALUES 2
#define PSMP_MAXIMUM_SYSAPP_CLAIM_VALUES 4

typedef struct _PS_PKG_CLAIM {
	ULONG_PTR Flags;     // PSM_ACTIVATION_TOKEN_*
	ULONG_PTR Origin;    // appmodel.h enum PackageOrigin
} PS_PKG_CLAIM, * PPS_PKG_CLAIM;

#define CONSOLE_DETACHED_PROCESS	((HANDLE)-1)
#define CONSOLE_NEW_CONSOLE			((HANDLE)-2)
#define CONSOLE_CREATE_NO_WINDOW	((HANDLE)-3)

#define SYSTEM_ROOT_CONSOLE_EVENT 3

#define CONSOLE_READ_NOREMOVE   0x0001
#define CONSOLE_READ_NOWAIT     0x0002
#define CONSOLE_READ_VALID      (CONSOLE_READ_NOREMOVE | CONSOLE_READ_NOWAIT)

#define CONSOLE_GRAPHICS_BUFFER  2
//ProcessParameters->ConsoleFlags [kernelbase.dll!ConsoleInitialize]
#define CONSOLE_IGNORE_CTRL_C		0x1
#define CONSOLE_HANDLE_REFERENCE	0x2 //IsReferenceHandle win 10 1803
#define CONSOLE_USING_PTY_REFERENCE 0x4 //win 10 1809

typedef struct _CONSOLE_REFERENCE {
	PHANDLE ConsoleRererenceHandle;//0x0
	UCHAR	ConsoleRererenceType; // ConsoleHandleType//IsPseudoConsole[PtyRererence] 0x0 = ReferenceConsole //0x1 = PseudoConsole
}CONSOLE_REFERENCE, * PCONSOLE_REFERENCE;

// This structure is part of an ABI shared with the rest of the operating system.
// HPCON Pointer of
typedef struct _PseudoConsole 
{
	// hSignal is a anonymous pipe used for out of band communication with conhost.
	// It's used to send the various PTY_SIGNAL_* messages.
	HANDLE hSignal;
	// The "server handle" in conhost represents the console IPC "pipe" over which all console
	// messages, all client connect and disconnect events, API calls, text output, etc. flow.
	// The full type of this handle is \Device\ConDrv\Server and is implemented in
	// /minkernel/console/condrv/server.c. If you inspect conhost's handles it'll show up
	// as a handle of name \Device\ConDrv, because that's the namespace of these handles.
	//
	// hPtyReference is derived from that handle (= a child), is named \Reference and is implemented
	// in /minkernel/console/condrv/reference.c. While conhost is the sole owner and user of the
	// "server handle", the "reference handle" is what console processes actually inherit in order
	// to communicate with the console server (= conhost). When the reference count of the
	// \Reference handle drops to 0, it'll release its reference to the server handle.
	// The server handle in turn is implemented in such a way that the IPC pipe is broken
	// once the reference count drops to 1, because then conhost must be the last one using it.
	//
	// In other words: As long as hPtyReference exists it'll keep the server handle alive
	// and thus keep conhost alive. Closing this handle will make conhost exit as soon as all
	// currently connected clients have disconnected and closed the reference handle as well.
	//
	// This benefit of this system is that it naturally works with handle inheritance in
	// CreateProcess,  which ensures that the reference handle is safely duplicated and
	// transmitted from a parent process to a new child process, even if the parent
	// process exits before the OS has even finished spawning the child process.
	HANDLE hPtyReference;
	// hConPtyProcess is a process handle to the conhost instance that we've spawned for ConPTY.
	// The ChildProcess Conhost.exe ProcessHandle, but Created from Userland instead of kernelbase.dll!ConsoleLaunchServerProcess
	HANDLE hConPtyProcess;
} PseudoConsole;

// Signals
// These are not defined publicly, but are used for controlling the conpty via
//      the signal pipe.
#define PTY_SIGNAL_SHOWHIDE_WINDOW (1u)
#define PTY_SIGNAL_CLEAR_WINDOW (2u)
#define PTY_SIGNAL_REPARENT_WINDOW (3u)
#define PTY_SIGNAL_RESIZE_WINDOW (8u)

// CreatePseudoConsole Flags
#ifndef PSEUDOCONSOLE_INHERIT_CURSOR
#define PSEUDOCONSOLE_INHERIT_CURSOR (0x1)
#endif
#ifndef PSEUDOCONSOLE_RESIZE_QUIRK
#define PSEUDOCONSOLE_RESIZE_QUIRK (0x2)
#endif
#ifndef PSEUDOCONSOLE_WIN32_INPUT_MODE
#define PSEUDOCONSOLE_WIN32_INPUT_MODE (0x4)
#endif
#ifndef PSEUDOCONSOLE_PASSTHROUGH_MODE
#define PSEUDOCONSOLE_PASSTHROUGH_MODE (0x8)
#endif

#define  PS_MITIGATION_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_ON			0x10000000
#define  PS_MITIGATION_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_OFF			0x20000000
#define  PS_MITIGATION_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_MASK				0x30000000

#define  PS_MITIGATION_OLD_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_ON		0x1000000
#define  PS_MITIGATION_OLD_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_OFF		0x2000000
#define  PS_MITIGATION_OLD_OPTION3_FSCTL_SYSTEM_CALL_DISABLE_MASK			0x3000000

typedef struct _PS_MITIGATION_OPTIONS_MAP
{
	ULONG_PTR Map[3]; // 2 < 20H1
} PS_MITIGATION_OPTIONS_MAP, * PPS_MITIGATION_OPTIONS_MAP;

// private
typedef struct _PS_MITIGATION_AUDIT_OPTIONS_MAP
{
	ULONG_PTR Map[3]; // 2 < 20H1
} PS_MITIGATION_AUDIT_OPTIONS_MAP, * PPS_MITIGATION_AUDIT_OPTIONS_MAP;

// private
typedef struct _PS_SYSTEM_DLL_INIT_BLOCK
{
	ULONG Size;
	ULONG_PTR SystemDllWowRelocation;
	ULONG_PTR SystemDllNativeRelocation;
	ULONG_PTR Wow64SharedInformation[16]; // use WOW64_SHARED_INFORMATION as index
	ULONG RngData;
	union
	{
		ULONG Flags;
		struct
		{
			ULONG CfgOverride : 1;
			ULONG Reserved : 31;
		};
	};
	PS_MITIGATION_OPTIONS_MAP MitigationOptionsMap;
	ULONG_PTR CfgBitMap;
	ULONG_PTR CfgBitMapSize;
	ULONG_PTR Wow64CfgBitMap;
	ULONG_PTR Wow64CfgBitMapSize;
	PS_MITIGATION_AUDIT_OPTIONS_MAP MitigationAuditOptionsMap; // REDSTONE3
} PS_SYSTEM_DLL_INIT_BLOCK, * PPS_SYSTEM_DLL_INIT_BLOCK;

#define WIN32K_SYSCALL_FILTER_STATE_ENABLE 0x1
#define WIN32K_SYSCALL_FILTER_STATE_AUDIT 0x2

// private
typedef struct _WIN32K_SYSCALL_FILTER
{
	ULONG FilterState;
	ULONG FilterSet;
} WIN32K_SYSCALL_FILTER, * PWIN32K_SYSCALL_FILTER;
typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

#define PROCESSOR_FEATURE_MAX 64
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign,
	NEC98x86,
	EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;
typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;
	volatile KSYSTEM_TIME InterruptTime;
	volatile KSYSTEM_TIME SystemTime;
	volatile KSYSTEM_TIME TimeZoneBias;
	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;
	WCHAR NtSystemRoot[260];
	ULONG MaxStackTraceDepth;
	ULONG CryptoExponent;
	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	ULONG AitSamplingValue;
	ULONG AppCompatFlag;
	ULONGLONG RNGSeedVersion;
	ULONG GlobalValidationRunlevel;
	LONG TimeZoneBiasStamp;
	ULONG NtBuildNumber;
	NT_PRODUCT_TYPE NtProductType;
	BOOLEAN ProductTypeIsValid;
	UCHAR Reserved0[1];
	USHORT NativeProcessorArchitecture;
	ULONG NtMajorVersion;
	ULONG NtMinorVersion;
	BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
	ULONG Reserved1;
	ULONG Reserved3;
	volatile ULONG TimeSlip;
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	ULONG BootId;
	LARGE_INTEGER SystemExpirationDate;
	ULONG SuiteMask;
	BOOLEAN KdDebuggerEnabled;
	union
	{
		UCHAR MitigationPolicies;
		struct
		{
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};
	USHORT CyclesPerYield;
	volatile ULONG ActiveConsoleId;
	volatile ULONG DismountCount;
	ULONG ComPlusPackage;
	ULONG LastSystemRITEventTickCount;
	ULONG NumberOfPhysicalPages;
	BOOLEAN SafeBootMode;
	UCHAR VirtualizationFlags;
	UCHAR Reserved12[2];
	union
	{
		ULONG SharedDataFlags;
		struct
		{
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG DbgMultiSessionSku : 1;
			ULONG DbgMultiUsersInSessionSku : 1;
			ULONG DbgStateSeparationEnabled : 1;
			ULONG SpareBits : 21;
		};
	};
	ULONG DataFlagsPad[1];
	ULONGLONG TestRetInstruction;
	LONGLONG QpcFrequency;
	ULONG SystemCall;
	union
	{
		ULONG AllFlags;
		struct
		{
			ULONG Win32Process : 1;
			ULONG Sgx2Enclave : 1;
			ULONG VbsBasicEnclave : 1;
			ULONG SpareBits : 29;
		};
	} UserCetAvailableEnvironments;
	ULONGLONG SystemCallPad[2];
	union
	{
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
		struct
		{
			ULONG ReservedTickCountOverlay[3];
			ULONG TickCountPad[1];
		};
	};
	ULONG Cookie;
	ULONG CookiePad[1];
	LONGLONG ConsoleSessionForegroundProcessId;
	ULONGLONG TimeUpdateLock;
	ULONGLONG BaselineSystemTimeQpc;
	ULONGLONG BaselineInterruptTimeQpc;
	ULONGLONG QpcSystemTimeIncrement;
	ULONGLONG QpcInterruptTimeIncrement;
	UCHAR QpcSystemTimeIncrementShift;
	UCHAR QpcInterruptTimeIncrementShift;
	USHORT UnparkedProcessorCount;
	ULONG EnclaveFeatureMask[4];
	ULONG TelemetryCoverageRound;
	USHORT UserModeGlobalLogger[16];
	ULONG ImageFileExecutionOptions;
	ULONG LangGenerationCount;
	ULONGLONG Reserved4;
	volatile ULONG64 InterruptTimeBias;
	volatile ULONG64 QpcBias;
	ULONG ActiveProcessorCount;
	volatile UCHAR ActiveGroupCount;
	UCHAR Reserved9;
	union
	{
		USHORT QpcData;
		struct
		{
			volatile UCHAR QpcBypassEnabled : 1;
			UCHAR QpcShift : 1;
		};
	};

	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;
	XSTATE_CONFIGURATION XState;
	KSYSTEM_TIME FeatureConfigurationChangeStamp;
	ULONG Spare;
	ULONG64 UserPointerAuthMask;
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;
typedef enum _HARDERROR_RESPONSE_OPTION
{
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem,
	OptionOkNoWait,
	OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes,
	ResponseTryAgain,
	ResponseContinue
} HARDERROR_RESPONSE;

#define HARDERROR_OVERRIDE_ERRORMODE 0x10000000

typedef struct _APPX_PROCESS_CONTEXT
{
	PSECURITY_CAPABILITIES AppXSecurityCapabilities;//0 AppXContainerSecurityCapabilities
	LPCWSTR AppXDllDirectory;//8
	LPCWSTR AppXCurrentDirectory;//16 
	PCWSTR PackageFullName;//24
	HANDLE EventHandle;//32
	HANDLE DuplicatedProcessHandle;//40
	ULONG AppXProcessContextLocked; //48 Warning! uncorrected!
	//Mapped: C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.SkypeApp_15.83.3409.0_x86__kzf8qxf38zg5c\S-1-5-21-xxxxxxxxxx-xxxxxxxx-xxxxxxxxxx-xxxx.pckgdep
	HANDLE SectionHandle;//56 //Package Dependency Data 
	PVOID LocalBaseAddress;//64 
	PVOID RemoteBaseAddress;//72
	union {
		ULONG AppXFlags; //80 BYTE?
		struct
		{
			UCHAR AppXProtectedProcessLight : 1;
			UCHAR AppXGlobalizationOverride : 1;
			UCHAR AppXManifestDetected : 1;
			UCHAR SpareBits1 : 5;
			UCHAR SpareBits2 : 8;
			USHORT Reserved : 16;
		}s1;
	}u1;
	LPCWSTR AppXRedirectionDllName;//88
}APPX_PROCESS_CONTEXT, * PAPPX_PROCESS_CONTEXT;

typedef struct _DESKTOP_APPX_ACTIVATION_INFO
{
	BOOLEAN ActivationTracking;
	HANDLE Semaphore; //TrackingSemaphore
}DESKTOP_APPX_ACTIVATION_INFO, * PDESKTOP_APPX_ACTIVATION_INFO;

//APP_EXECUTION_ALIAS_INFO_EXTEND Uncorrected! Warning! Unstable Struct!
// ERROR!
class ExtendedAppExecutionAliasInfo
{
public:

	//private:
	PWSTR AppXPackageName = NULL;//0 WCHAR [256]
	LPCWSTR AppAliasBaseImagePath = NULL;//8
	HANDLE TokenHandle = NULL;//16
	LPCWSTR PackageFamilyName = NULL;//24 
	BOOL BreakawayModeLaunch = FALSE;//32
	PWSTR AppExecutionAliasRedirectPackages = NULL;	//40
	PWSTR AliasPackagesIsolationPrefix = NULL;		//48

	std::wstring PresentRawImagePath;
	std::wstring AppXPackageName2;
	std::wstring AppAliasLaunchImagePath2;
	HANDLE TokenHandle2 = NULL;
	std::wstring Commandline;
	//DesktopAppXActivationInfo 
	PDESKTOP_APPX_ACTIVATION_INFO DesktopAppXActivationInfo = NULL;

	ExtendedAppExecutionAliasInfo(LPCWSTR ImagePath = NULL, PVOID Unknow = NULL) {};
	BOOLEAN Load(HANDLE TokenHandle); //BOOLEAN Load(ExtendedAppExecutionAliasInfo ,HANDLE TokenHandle);
}; //184

// Warning! Unstable Struct!
class ExtendedAppExecutionAliasInfo_New
{
public:
	//private:
	PWSTR AppXPackageName = NULL;//0 WCHAR [256]
	LPCWSTR AppAliasBaseImagePath = NULL;//8
	HANDLE TokenHandle = NULL;//16
	LPCWSTR PackageFamilyName = NULL;//24
	BOOL BreakawayModeLaunch = FALSE;//32
	PWSTR AppExecutionAliasRedirectPackages = NULL;//40
	std::wstring PresentRawImagePath;//48
	std::wstring AppXPackageName2;//80
	std::wstring AppAliasLaunchImagePath2;//112
	std::wstring Unknow;//144
	HANDLE TokenHandle2 = NULL;//176 FileHandle???
	std::wstring Commandline;//184
	PDESKTOP_APPX_ACTIVATION_INFO DesktopAppXActivationInfo = NULL;//216
}; //224

/*
class ExtendedAppExecutionAliasInfo
{
public:

	//private:
	PWSTR AppXPackageName = NULL;//0 WCHAR [256]
	LPCWSTR AppAliasBaseImagePath = NULL;//8
	HANDLE TokenHandle = NULL;//16
	LPCWSTR BreakawayCommandeLine = NULL;//24
	BOOL BreakawayModeLaunch = FALSE;//32
	std::wstring PresentRawImagePath;//40 -- 48
	std::wstring AppXPackageName2;//72 -- 80
	std::wstring AppAliasLaunchImagePath2;//104 -- 112
	HANDLE TokenHandle2 = NULL;//136 FileHandle???
	std::wstring Commandline;//144
	//DesktopAppXActivationInfo 176 + 8
	PDESKTOP_APPX_ACTIVATION_INFO DesktopAppXActivationInfo = NULL;//176

	ExtendedAppExecutionAliasInfo(LPCWSTR ImagePath = NULL, PVOID Unknow = NULL) {};
	BOOLEAN Load(HANDLE TokenHandle) {}; //BOOLEAN Load(ExtendedAppExecutionAliasInfo ,HANDLE TokenHandle);
}; //184
*/

// rev
enum AppType
{
	InvaildApp = 0,
	GeneralUWPApp = 1,
	MultipleInstancesUWPApp = 2,
	ConsoleUWPApp = 3,
	ContainerApp = 4,
	Win32App = 5,
	MaxNumberApp
};


typedef struct _ACTIVATION_TOKEN_INFO
{
	HANDLE ActivationTokenHandle;
	LPWSTR PackageBnoIsolationPrefix; //in RemoteProcess explorer.exe 
}ACTIVATION_TOKEN_INFO, * PACTIVATION_TOKEN_INFO;

// AppXDeploymentExtensions.onecore.dll 
// Microsoft Windows AppXDeployment Server
// AppModel::TrustLevel_AppSilo
namespace AppModel
{
	enum
	{
		RuntimeBehavior_None,//?? RuntimeBehavior_None
		RuntimeBehavior_Universal,// RuntimeBehavior_Universal? RuntimeBehavior_Windows_app
		RuntimeBehavior_DesktopBridge, //RuntimeBehavior_PackagedClassicApp, https://learn.microsoft.com/en-us/windows/apps/get-started/intro-pack-dep-proc
		RuntimeBehavior_Win32App,// including apps packaged with external location.[PackageExternalLocation, PackageExternal]
		RuntimeBehavior_AppSilo // ?
	};

	enum
	{
		AppLifecycleBehavior_None,
		AppLifecycleBehavior_Unmanaged,
		AppLifecycleBehavior_SystemManaged,
	};
	enum
	{
		TrustLevel_None,
		TrustLevel_PartialTrust,
		TrustLevel_FullTrust,
	};
};

// StateRepository::Entity::Activation Uncorrected
#define APPMODEL_ACTIVATION_FULL_TRUST 0x4//SetTrustLevel mediumIL[2]
#define APPMODEL_ACTIVATION_SUPPORTS_MULTIPLE_INSTANCES 0x8//SetSupportsMultipleInstances
#define APPMODEL_ACTIVATION_PACKAGEDCLASSICAPP 0x10 //SetRuntimeBehavior
#define APPMODEL_ACTIVATION_WIN32APP 0x20
#define APPMODEL_ACTIVATION_IS_CONSOLE_SUBSYSTEM 0x40//SetIsConsoleSubsystem
#define APPMODEL_ACTIVATION_PARTIAL_TRUST 0x80//SetTrustLevel appContainer[1] "Windows.PartialTrustApplication"
#define APPMODEL_ACTIVATION_WINDOWSAPP 0x100 //SetRuntimeBehavior
#define APPMODEL_ACTIVATION_APPSILO 0x200
#define APPMODEL_ACTIVATION_UNMANAGED 0x400
#define APPMODEL_ACTIVATION_SYSTEMMANAGED 0x800

// StateRepository::Entity::package packageWriteRedirectionCompatibilityShim
// 
// StateRepository::Entity::ApplicationExtension::ResetTrustLevelAndRuntimeBehaviorByCentennialEntrypoint
//  UPDATE ApplicationExtension SET Flags=((Flags | 0x14) & ~0x1A0) WHERE Entrypoint='Windows.FullTrustApplication';"
//  "UPDATE ApplicationExtension SET Flags=((Flags | 0x90) & ~0x124) WHERE Entrypoint='Windows.PartialTrustApplication';",

// Uncorrected
#define APPMODEL_PACKAGE_RUN_FULL_TRUST 0x40//PackageNeedsToSetFlag [Capability]
#define APPMODEL_PACKAGE_IN_RELATED_SET 0x80
#define APPMODEL_PACKAGE_MORERECENTLY_STAGED 0x400 //StateRepository::Migration::Deployment_Package_PopulateMostRecentlyStaged
#define APPMODEL_PACKAGE_CONTENT_FULL_TRUST 0x800000 //PackageNeedsToSetFlag
// AppXDeploymentServer.dll 无能为力

//
// uap10:RuntimeBehavior	:
// Specifies the run time behavior of the app.
//
// "packagedClassicApp"—a WinUI 3 app, or a Desktop Bridge app(Centennial).For a WinUI 3 app, usually goes with a TrustLevel of "mediumIL" (but "appContainer" is also an option).
// "win32App"—any other kind of Win32 app, including an app packaged with external location.Usually goes with a TrustLevel of "mediumIL" (but "appContainer" is also an option).
// "windowsApp"—a Universal Windows Platform(UWP) app.Always goes with a TrustLevel of "appContainer".
// 
// All share common properties(some declared in appxmanifest.xml), and run as a process with package identity and application identity.
// You can think of them as being in two groups.One group is UWP apps("windowsApp"); the other is Windows.exes with main or WinMain("packagedClassicApp" or "win32App").That second group is also known as desktop apps.
//


// BasepGetPackagedAppInfoForFile(DosPathName, CurrentTokenHandle,TRUE, &ExtendedPackagedAppContext);
// 根据Windows 11 Insider 26016.1000 逆向，后部分结构偏移与 Windows 11 21H2 有细微差异 [ACTIVATION_TOKEN_INFO ActivationTokenInfo/HANDLE TokenHandle]
// [PackagedCreateProcess::GetPackagedDataForFileInternal] StateRepository::Cache::Entity::Package_NoThrow

namespace ExtendedPackagedAppContext
{
	struct ExtendedPackagedAppContext
	{
		// Breakaway ? NoOriginatedStore ?
		BOOLEAN Breakaway; //PackageOrigin != PackageOrigin_Store AppNotBelongWindowsStore [The package originated from the Windows Store.]
		BOOLEAN Reserved;
		WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];//2
		WCHAR PackageFullName[PACKAGE_FULL_NAME_MAX_LENGTH + 1];//262
		LPWSTR PackageImagePath;//520

		LPWSTR PresentCurrentDirectory;//528
		LPWSTR PresentAppCategory;//536 [ExtendedPackagedAppContext::SetCategory]
		BOOLEAN IsAppExecutionAliasType;//544

		// SqlLite3: [StateRepository-Machine.srd, StateRepository-Deployment.srd]
		// [Windows AppXSvc: C:\Windows\system32\svchost.exe -k wsappx -p] -> [StateRepository::Entity::Activation::]
		// 
		// AppXDeploymentExtensions.onecore.dll!StateRepository::Entity::PackageExtension::GenerateActivationIfNecessary
		//   AppXDeploymentExtensions.onecore.dll!StateRepository::Entity::Activation::GenerateActivationKey
		//   AppXDeploymentExtensions.onecore.dll!StateRepository::Entity::Activation::TryGetByActivationKey
		//   AppXDeploymentExtensions.onecore.dll!StateRepository::Entity::Activation::Add(__int64 ActivationData, StateRepository::Database *a2) -> ..\Activation\Data-> 
		//     INSERT INTO Activation (_Revision, ActivationKey, Flags, HostId, Executable, Entrypoint, RuntimeType, StartPage, ResourceGroup, _Dictionary) VALUES(?,?,?,?,?,?,?,?,?,?);
		// 
		// Activation Type 
		// [PackagedCreateProcess::GetAppType(StateRepository::Cache::Entity::Application_NoThrow* Application)] HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data->Flags
		// [PackagedCreateProcess::GetAppType(StateRepository::Cache::Entity::Activation_NoThrow* Activation)]   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Data->Flags
		DWORD AppType;//548 0,1,2,3,4,5?  [PackagedCreateProcess::GetAppType] 

		ACTIVATION_TOKEN_INFO PresentActivationTokenInfo;//552
		LPWSTR FinalPath;//568
		LPWSTR AppPackageLocation;//576 [ExtendedPackagedAppContext::SetAppLocation] CurrentDirectoryParent
		LPWSTR ExeLocation;//584 PackageName? [ExtendedPackagedAppContext::SetExeLocation]  ChildCurrentDirectory
		LPWSTR CurrentDirectory;//592 [ExtendedPackagedAppContext::SetCurrentDirectoryW]
		LPWSTR AppCategory;//600 Windows.AppExecutionAlias Windows.FullTrustProcess [ExtendedPackagedAppContext::SetCategory]

		// Uncorrected! [PackagedCreateProcess::GetPackagedDataForFileInternal -> StateRepository::Cache::Entity::Package_NoThrow StateRepositoryCachePackage.m_flags]
		// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data -> Flags
		BOOLEAN Unknow1;//608 0x1
		BOOLEAN Unknow2;//609 0x800
		BOOLEAN Unknow3;//610 0x400000
		BOOLEAN UnknowPadding;//611
		// ExtendedPackagedAppContext::SetAppLocation
		// PackagedCreateProcess::IsTrustLabelAceSupported(AppPathType)
		PackagePathType AppPathType;//612 DWORD PackageExternalLocationFlags2 [PackagedCreateProcess::IsTrustLabelAceSupported]
		LPWSTR PackageFamilyName;//616 ExtendedPackagedAppContext::SetPackageFamilyName
		ACTIVATION_TOKEN_INFO ActivationTokenInfo;//624
		DESKTOP_APPX_ACTIVATION_INFO DesktopAppXActivationInfo;//640
	};
	
};

// OSVERSIONINFOEXW lpVersionInformation = { 0 };
// WTF RB Tree? xxx nonono, but Merge COBALT_MODFLAG
// DO NOT USE!
/*
typedef struct _COBALT_MODULE_FLAGS//32
{
	PVOID a;
	union
	{
		ULONGLONG Flag1;//16
		struct
		{
			ULONG Unknow;
			ULONG Reserved;
		};
	};

	union
	{
		ULONG Flag2;//16
		struct
		{
			WORD unknow1;
			char w;
			char z;
		}s1;
	}u1;
	char c;//20
	char d;//21
	char e;//22
	char f;//23
	union
	{
		ULONGLONG Flag3;//24
		struct
		{
			char CoreFlagXor;//24 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40
			char CoreFlag2Xor2;//25  0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40
			char XOR3;//26 win 11
			char Reserved[6];
		}s2;
	}u2;
}COBALT_MODULE_FLAGS, * PCOBALT_MODULE_FLAGS;
*/

typedef WORD TAG;
typedef DWORD TAGID;
typedef DWORD TAGREF;
typedef PVOID HSDB;

#define MAX_INDEXES             10
//
// This is a flag stored for each index.
// Currently it is only used to flag "unique key" types.
//
#define SHIMDB_INDEX_UNIQUE_KEY 0x00000001

// index could be of 2 types:
// containing simply all record and containing only
// "unique" keys with the records linked (the records have to be sorted for this
// type of index to work)
typedef struct _INDEX_INFO {
	TAGID       tiIndex;            // points at the INDEX_BITS tag
	TAG         tWhich;             // what tag is being indexed
	TAG         tKey;               // what subtag is the key?
	BOOL        bActive;            // are we actually indexing now?
	BOOL        bUniqueKey;         // are the keys unique?
	ULONGLONG   ullLastKey;
	DWORD       dwIndexEntry;       // offset to the next available index entry
	DWORD       dwIndexEnd;         // one byte past the end of the index block
	DWORD       dwFlags;
} INDEX_INFO, * PINDEX_INFO;

//
// Flags for use in DB structure DB.dwFlags
//

#define DB_IN_MEMORY           0x00000001
#define DB_GUID_VALID          0x00000002
// stringtable is a subdatabase that's created on the side
// uncorrected!
typedef struct _DB {
	// used for both read and write

	HANDLE      hFile;
	PVOID       pBase;              // for  both memory-mapping & buffered writes
	BOOL        bWrite;             // was it opened with create?
	DWORD       dwSize;             // the size of the whole db, in bytes

	DWORD       dwFlags;            // flags (such as IN-memory flag)

	GUID        guidDB;             // optional id for the database

	DWORD       dwIndexes;          // the number of indexes
	INDEX_INFO  aIndexes[MAX_INDEXES];  // data for the indexes

	// stuff that's used for read
	HANDLE      hSection;           // for memory-mapping
	TAGID       tiStringTable;      // pointer to the stringtable for string handling
	BOOL        bIndexesScanned;    // have the indexes been looked at?

	// stuff that's used for write
	struct _DB* pdbStringTable;    // stringtable is a subdatabase that's created on the side
	PVOID       pStringHash;        // stringtable hash (same info as in stringtable)
	DWORD       dwAllocatedSize;    // the size allocated for buffered writes
	BOOL        bWritingIndexes;    // are we in the process of allocating index space?
	TAGID       tiIndexes;          // used during index allocation

	//
	// BUGBUG Hack alert read from unaligned (v1.0) database is enabled here
	//
	BOOL        bUnalignedRead;


#ifdef WIN32A_MODE
	PVOID       pHashStringBody;    // hash of the strings located within the body
	PVOID       pHashStringTable;   // hash for the strings in the stringtable
#endif

#ifndef WIN32A_MODE
	UNICODE_STRING ustrTempStringtable; // string table temp filename
#else
	LPCTSTR        pszTempStringtable;
#endif

} DB, * PDB;

//
// We're using the high 4 bits of the TAGID to
// say what PDB the TAGID is from. Kludge? Perhaps.
//
#define PDB_MAIN            0x00000000
#define PDB_TEST            0x10000000

// all other entries are local (custom) pdbs

#define PDB_LOCAL           0x20000000

#define TAGREF_STRIP_TAGID  0x0FFFFFFF
#define TAGREF_STRIP_PDB    0xF0000000

typedef WCHAR* PWSZ;

#define SDB_MAX_EXES 16
#define SDB_MAX_LAYERS 8
#define SDB_MAX_SDBS 16

typedef struct tagSDBQUERYRESULT {
	TAGREF trExes[SDB_MAX_EXES];	//0x00
	DWORD  dwExeFlags[SDB_MAX_EXES];//0x40
	TAGREF trLayers[SDB_MAX_LAYERS];//0x80
	DWORD  dwLayerFlags;			//0xA0
	TAGREF trApphelp;				//0xA4
	DWORD  dwExeTagsCount;			//0xA8
	DWORD  dwLayerTagsCount;		//0xAC
	GUID   guidID;					//0xB0
	DWORD  dwFlags;					//0xC0
	DWORD  dwCustomSDBMap;			//0xC4
	GUID   rgGuidDB[SDB_MAX_SDBS];	//0xC8
} SDBQUERYRESULT, * PSDBQUERYRESULT;//0x1C8

#define APPCOMPAT_EXE_DATA_MAGIC 0xAC0DEDAB
#define SWITCHCONTEXT_BRANCH_GUID_MAXCOUNT 48

// ShimLog ShimDebug
#pragma pack(4)									// Require fixed aligment.
//private
typedef struct _ASL_LOG_ENTRY
{
	UCHAR  AslLogName[64];
	PVOID AslLogData;//64
	ULONG WrittenDataLength;//72
	ULONG AlignLength;//76 HeapAllocAlignBoundary MaxLengthPreCopy?  2的倍数? 0x400, 0x1000
	ULONG AppCompatLogFlags;//80 _ASL_LOG_LEVEL
	ULONG Reserved;//84
	ULONG EntryStateLock;//88
}ASL_LOG_ENTRY, * PASL_LOG_ENTRY;//92
#pragma pack()									// Restore previous aligment.

// UnCorrected!
typedef struct _ASL_LOG
{
	ASL_LOG_ENTRY* LogInfoEntryAddress;//链?
	ASL_LOG_ENTRY  LogInfoEntry;//0x8
	/* xxxxxx do not use, uncorrected
	ULONG Padding;			//0x64
	RTL_CRITICAL_SECTION Lock;//0x68

	PVOID AslLogProcessHeap;//0x90
	ULONG WrittenDataLength;//0x98

	ULONGLONG DefaultAlignLength;//0xA8

	PVOID DataOffset;//0xB0 Current
	PVOID AslLogData;//0xB8
	WCHAR LogFilePath[MAX_PATH];//0xC0 + 208

	HANDLE EtwRegHandle;//0x2C8
	*/
	//阿巴阿巴....
	//....
}ASL_LOG, *PASL_LOG;

//AppCompatData Fix fix
typedef struct _APPCOMPAT_EXE_DATA {
	WCHAR szShimEngine[MAX_PATH];				//+0x0 C:\Windows\System32\apphelp.dll
	ULONG cbSize;								//+0x208
	ULONG dwMagic;								//+0x20c 
	ULONG dwFlags;								//+0x210
	ULONG dwMachine;							//+0x214
	SDBQUERYRESULT SdbQueryResult;				//+0x218

	ASL_LOG_ENTRY AslLogEntry[11];				//+0x3e0  as it was on win 8 SepApplyDebugPolicy struct _ASL_LOG *g_ShimDebugLog/AslLogCreate/AslLogPublishToPeb
	ULONG AslReserved1;							//+0x7d4
	ULONGLONG AslReserved2;						//+0x7d8
				
	struct
	{
		ULONGLONG ContextReference;				//+0x7e0 SwitchContextReferenceCount//SwitchBackContextReferenceNumber -- SbUpdateSwitchContextBasedOnDll ? SbSupportedOsList
		ULONG SwitchContextOSMatch;				//+0x7e8 BOOL? PlatformIdMatch Checked?
		ULONG SdbTraceEnabled;					//+0x7ec BOOL?
		HANDLE SdbTraceHandle;					//+0x7f0 EtwEvent
		//
		// Windows Internals, Part 1: Chapter 3->Processes and jobs->SwitchBack (p171-p173)
		//=====================================================
		// SwitchBack parses this information and correlates it with embedded information in SwitchBackcompatible DLLs (in the .sb_data image section) to 
		// decide which version of an affected API should be called by the module.Because SwitchBack works at the loaded - module level, 
		// it enables a process to have both legacy and current DLLs concurrently calling the same API, yet observing different results.
		// 
		// SWITCHBRANCH_CACHED_MODULE_TABLE->SWITCHBRANCH_MODULE_TABLE_ENTRY
		// 
		// SbPrepareSwitchContext csrstub.exe->IgnoreSwitchContext ?
		// Windows PlatformId SwitchContext for Fine-Grained PlatformOverride AppCompat Branch Function/API
		// ->trExes & trLayers
		// 
		// kernel32.dll!SbPrepareSwitchContext
		// kernel32.dll!SbpCreateSwitchContext
		// kernel32.dll!SbpMergeApphackContexts
		// kernel32.dll!SbpQueryContexts
		//  apphelp.dll!SdbQueryContext
		// SdbQueryResult->trExes and SdbQueryResult->trLayers
		// 48*16 = 768 0x300
		//
		struct
		{
			ULONGLONG ProcessOsMaxVersionTested;//+0x7f8 SupportOS->MaxVersionTested/SupportOSVersionTest/ProcessOsMaxVersionTested[SbGetProcessOsMaxVersionTested]
			DWORD DeviceFamily;					//+0x800
			DWORD Reserved;						//+0x804
			PACKAGE_VERSION	MinPackageVersion;	//+0x808 IsPackageImage-> 6.2.0.0
			GUID MaxSupportOSGuid;				//+0x810 for PlatformId 48 [trExesGenericPlatformGuid] ?
			GUID MinSupportOSGuid;				//+0x820 0x820 - 0x7e0 = 0x40 = 64 [trLayersGenericPlatformGuid]
			ULONG dwOSVersionCheckFormType;		//+0x830 d.. with SubSystemVersion[1]/MaxversionTested/OperatingSystemVersion/4?/SdbContextQuery +64
			DWORD BranchGuidTotalCount;			//+0x834
			GUID BranchGuidList[SWITCHCONTEXT_BRANCH_GUID_MAXCOUNT];//0x838
		}SwitchBackContext;// Size = 0x340 should be SwitchBranch
	};

	ULONG dwParentProcessId;					//+0xb38
	WCHAR szParentImageName[MAX_PATH];			//+0xb3c
	WCHAR CompatLayerEnvValue[0x100];			//+0xd44 __COMPAT_LAYER 	WCHAR CompatLayerEnvValue[0x200] ???
	// LayerName ? CommandLayerName??
	WCHAR Reserved[0x100];						//+0xf44 maybe, UnCorrected! __COMMAND_LINE_OVERRIDE__// __PROCESS_HISTORY?
	ULONG ImageFileSize;						//+0x1144 
	ULONG ImageCheckSum;						//+0x1148
	BOOL AppCompatSupportOSMatchExpect;			//+0x114c
	BOOL ImageIsPackage;						//+0x1150
	BOOL SxsSupportedOSVersionSpecified;		//+0x1154
	BOOL RunLevelSpecified;						//+0x1158
	BOOL OtherCompatModeEnabled;				//+0x115c
	ACTCTX_REQUESTED_RUN_LEVEL RunLevel;		//+0x1160
	ULONG Reserved2;							//+0x1164 [uncorrected] UiAccess?

	ULARGE_INTEGER ManagerFinalAppCompatFlag;	//+0x1168
	PVOID HookComInterface;						//+0x1170 ntdll!SE_COM_AddServer
	HANDLE ComponentOnDemandEtwEvent;			//+0x1178 ntdll!LdrpCheckComponentOnDemandEtwEvent, related to QuirkComponent CodeId?
	PVOID QuirksTable;							//+0x1180 指向一个结构 ApphelpCacheServiceMapQuirks//QuirkManager
	ULONG QuirkTableSize;						//+0x1188 QuirkManagerFlags ?
	ULONG Reserved3;							//+0x118c QuirkUnknowReserved

	UCHAR CobaltProcFlagStruct[40];				//+0x1190 40 = 0x28  ->0x11B8 DO NOT TRY TO RE THIS.QAQ _COBALT_PROCFLAG

	ULONG PdbBufferLength;						//+0x11b8
	ULONG dwStructSize;							//+0x11bc PdbBufferOffset
} APPCOMPAT_EXE_DATA, * PAPPCOMPAT_EXE_DATA;	//+0x11c0 == 4544
// PdbBuffer next to  _APPCOMPAT_EXE_DATA

//
// SE_InitializeEngine->SeEngineCreate Create: 
// ManagerPointerList in Heap: g_Engine
// [0] FlagManager		0x30
// [1] QuirkManager		0x30
// [2] ShimManager		0x60
// [3] HookManager		0x8A0
// [4] ?
// [5] ModuleTracker	0x48
// [6] Router			0x18
// [7] ComRouter		0xC0
//

typedef enum {
	FIX_SHIM,
	FIX_PATCH,
	FIX_LAYER,
	FIX_FLAG
} FIXTYPE;

typedef enum {
	FLAG_USER,
	FLAG_KERNEL
} FLAGTYPE;

//FIX_FLAG
typedef struct _APPCOAMPAT_FLAG_LUA
{
	struct
	{
		UCHAR RunAsInvoker : 1;				// 应用程序应使用与父进程相同的 Windows 权限和用户权限运行。此设置相当于没有应用程序的应用程序兼容性数据库。应用程序以与启动它的父进程相同的权限启动，这减少了应用程序的安全风险。这是因为对于大多数应用程序来说，父级是 Explorer.exe，它作为标准用户应用程序运行。从以完全管理员身份运行的 cmd.exe shell 启动的 RunAsInvoker 应用程序将使用完全管理员访问令牌“以调用者身份运行”。
		UCHAR RunAsHighest : 1;				// 该应用程序可由管理员和标准用户运行，并根据用户的特权和用户权限调整其行为;该应用程序需要比标准用户更高的特权和用户权限，但不要求用户是本地管理员组的成员。
		UCHAR RunAsAdmin : 1;				// 应用程序应仅为管理员运行，必须使用完整的管理员访问令牌启动，并且无法在标准用户上下文中正确运行。此请求的执行级别标记是为要求用户是本地管理员组成员的 Windows Vista 之前的应用程序保留的。	
		UCHAR Reserved1 : 5;
		UCHAR Reserved2 : 8;
	} DisableUiAccess;
	struct
	{
		UCHAR RunAsInvoker : 1;				// 应用程序应使用与父进程相同的 Windows 权限和用户权限运行。此设置相当于没有应用程序的应用程序兼容性数据库。应用程序以与启动它的父进程相同的权限启动，这减少了应用程序的安全风险。这是因为对于大多数应用程序来说，父级是 Explorer.exe，它作为标准用户应用程序运行。从以完全管理员身份运行的 cmd.exe shell 启动的 RunAsInvoker 应用程序将使用完全管理员访问令牌“以调用者身份运行”。
		UCHAR RunAsHighest : 1;				// 该应用程序可由管理员和标准用户运行，并根据用户的特权和用户权限调整其行为;该应用程序需要比标准用户更高的特权和用户权限，但不要求用户是本地管理员组的成员。
		UCHAR RunAsAdmin : 1;				// 应用程序应仅为管理员运行，必须使用完整的管理员访问令牌启动，并且无法在标准用户上下文中正确运行。此请求的执行级别标记是为要求用户是本地管理员组成员的 Windows Vista 之前的应用程序保留的。	
		UCHAR Reserved1 : 5;
		UCHAR Reserved2 : 8;
	} EnableUiAccess;

	UCHAR NoVirtualization : 1;				// 关闭该应用程序的文件虚拟化和注册表虚拟化
	UCHAR NoSignatureCheck : 1;				// 关闭应用程序的签名检查
	UCHAR AdditiveRunAsHighest : 1;			// 当应用程序在没有人请求更高特权提升时接收RunAsHighest标志。这意味着，如果清单/AppCompatLayer是asInvoker/RunAsInvoker，将设置覆盖为RunAsHighest，但如果清单/AppCompatLayer是requireAdministrator/RunAsAdmin，没有任何影响。该标志将仅用于提高您的提升级别（到highestAvailable），而绝不会用于降低提升级别（从requireAdministrator）。
	UCHAR NoCfgCheck : 1;					// 0x800000000
	UCHAR NoImageExpansion : 1;				// 0x1000000000
	UCHAR Reserved3 : 3;
	UCHAR Reserved4 : 8;
	USHORT Reserved5 : 16;
}APPCOAMPAT_FLAG_LUA, * PAPPCOAMPAT_FLAG_LUA;

typedef struct _APPCOAMPAT_FLAG_INSTALL
{
	UCHAR GenericInstaller : 1;				// 与通用安装程序匹配。
	UCHAR SpecificInstaller : 1;			// 将应用程序标记为显示为旧版应用程序安装程序。标记文件后，SpecificInstaller 兼容性修复程序可以应用安装缓解措施，其中包括以管理员身份运行应用程序和应用 WRPMitigation 兼容性修复程序
	UCHAR SpecificNonInstaller : 1;			// 将应用程序标记为不是应用程序安装文件（如果 GenericInstaller 函数找到并怀疑该应用程序是安装程序）。应用此兼容性修复程序后，应用程序将不再提示提升权限，或执行其他与安装相关的操作。
	UCHAR Reserved1 : 5;
	UCHAR Reserved2 : 8;
	USHORT Reserved3;
	ULONG Reserved4;
}APPCOAMPAT_FLAG_INSTALL, * PAPPCOAMPAT_FLAG_INSTALL;

// #define ..*..FLAG or typedef struct .. union .. will be better?
// UnCorrected

typedef struct _COAMPAT_FIX_FLAG
{
	union
	{
		ULARGE_INTEGER FixFlag;
		//FLAG_MASK_KERNEL = 0x5005, [28]
		//FLAG_MASK_USER = 0x5008, [62]
		// 
		// ? typedef struct ... NTVDM_FLAGS, *PNTVDM_FLAGS ?
		// 
        //FLAGS_NTVDM1 = 0x5009,? [130]
        //FLAGS_NTVDM2 = 0x500A,? [18]
        //FLAGS_NTVDM3 = 0x500B,? [26]
		//FLAG_MASK_SHELL [Deprecated]??
		//FLAG_MASK_FUSION only 0x1
		//FLAG_PROCESSPARAM [2] EnableDEP: 0x20000:17 LoadLibraryRedirectFlag: 0x200000:21
		APPCOAMPAT_FLAG_LUA LuaFlags; //FLAG_LUA [6]
		APPCOAMPAT_FLAG_INSTALL InstallFlags; //FLAG_INSTALL [3]
	};
}COAMPAT_FIX_FLAG, * PCOAMPAT_FIX_FLAG;

// Private, winbasep.h
// ProcessParameters->WindowFlags = StartInfo->dwFlags;
#define STARTF_HASSHELLDATA			0x00000400
#define STARTF_TITLEISLOCALALLOCED	0x00004000

// [fontdrvhost.exe]
// 1: winlgon.exe!LaunchUmfdHostWithVirtualAccount				// wininit.exe->wininitext.dll!LaunchUmfdHostWithVirtualAccount
// 2: winlgon.exe!LaunchUmfdHostWithCurrentTokenUnconditional	// wininit.exe->wininitext.dll!LaunchUmfdHostWithCurrentTokenUnconditional
// since win 10 19H1/1903 [10.0.18362.1] 
#define STARTF_IGNOREGUIAPP			0x00010000					// Fake define lol, Do NOT care about it [uncorrected] fontdrvhost.exe only? CreateProcess only? win32k*?.sys fail to match ppi->usi->dwFlags???
#define STARTF_SHELLSHOWWINDOWS		0x00020000					// win32kfull.sys!xxxGetShellShowWindowCommand https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinkw-setshowcmd
#define STARTF_DESKTOPINHERIT		0x40000000					// services,exe!ScInitStartupInfo ?STARTF_TASKNOTCLOSABLE?  win32kbase.sys!xxxCreateThreadInfo
#define STARTF_SCREENSAVER			0x80000000					// RunScreenSaver(_WLSM_GLOBAL_CONTEXT* ,SCREEN_SAVER_DATA*, _WINLOGON_JOB **)  win32kbase.sys!xxxCreateThreadInfo

// TODO?
// NTKernel PDCRevocation

// PINIFILE_MAPPING_VARNAME->MappingFlags
#define INIFILE_MAPPING_WRITE_TO_INIFILE_TOO    0x00000001
#define INIFILE_MAPPING_INIT_FROM_INIFILE       0x00000002
#define INIFILE_MAPPING_READ_FROM_REGISTRY_ONLY 0x00000004
#define INIFILE_MAPPING_APPEND_BASE_NAME        0x10000000
#define INIFILE_MAPPING_APPEND_APPLICATION_NAME 0x20000000
#define INIFILE_MAPPING_SOFTWARE_RELATIVE       0x40000000
#define INIFILE_MAPPING_USER_RELATIVE           0x80000000

typedef struct _INIFILE_MAPPING_TARGET {
	struct _INIFILE_MAPPING_TARGET* Next;
	UNICODE_STRING RegistryPath;
} INIFILE_MAPPING_TARGET, * PINIFILE_MAPPING_TARGET;

typedef struct _INIFILE_MAPPING_VARNAME {
	struct _INIFILE_MAPPING_VARNAME* Next;
	UNICODE_STRING Name;
	ULONG MappingFlags;
	PINIFILE_MAPPING_TARGET MappingTarget;
} INIFILE_MAPPING_VARNAME, * PINIFILE_MAPPING_VARNAME;

typedef struct _INIFILE_MAPPING_APPNAME {
	struct _INIFILE_MAPPING_APPNAME* Next;
	UNICODE_STRING Name;
	PINIFILE_MAPPING_VARNAME VariableNames;
	PINIFILE_MAPPING_VARNAME DefaultVarNameMapping;
} INIFILE_MAPPING_APPNAME, * PINIFILE_MAPPING_APPNAME;
typedef CONST INIFILE_MAPPING_APPNAME* PCINIFILE_MAPPING_APPNAME;

typedef struct _INIFILE_MAPPING_FILENAME {
	struct _INIFILE_MAPPING_FILENAME* Next;
	UNICODE_STRING Name;
	PINIFILE_MAPPING_APPNAME ApplicationNames;
	PINIFILE_MAPPING_APPNAME DefaultAppNameMapping;
} INIFILE_MAPPING_FILENAME, * PINIFILE_MAPPING_FILENAME;
typedef CONST INIFILE_MAPPING_FILENAME* PCINIFILE_MAPPING_FILENAME;

typedef struct _INIFILE_MAPPING {
	PINIFILE_MAPPING_FILENAME FileNames;
	PINIFILE_MAPPING_FILENAME DefaultFileNameMapping;
	PINIFILE_MAPPING_FILENAME WinIniFileMapping;
	ULONG Reserved;
} INIFILE_MAPPING, * PINIFILE_MAPPING;
typedef CONST INIFILE_MAPPING* PCINIFILE_MAPPING;


// HKLM\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International
#define NLS_INVALID_INFO_CHAR  0xffff       /* marks cache string as invalid */

#define MAX_REG_VAL_SIZE       80           /* max size of registry value */

#define NLS_CACHE_MUTANT_NAME  L"NlsCacheMutant"  /* Name of NLS mutant cache */

// 
// Nls 结构大幅修改
// "s" 前一位常常为字符数
// basesrv.dll!NlsUpdateCacheInfo -> NtQueryMultipleValueKey: ValueBuffer 严格四字节Buffer分离
//
typedef struct _NLS_USER_INFO {
	WCHAR	LocaleName[86];						//0x00 sLocale
	WCHAR	sList[5];							//0xAC
	WCHAR	sDecimal[5];						//0xB6
	WCHAR	sThousand[5];						//0xC0
	WCHAR	sGrouping[11];						//0xCA
	WCHAR	sNativeDigits[12];					//0xE0
	WCHAR	sMonDecimalSep[5];					//0xF8
	WCHAR	sMonThousandSep[5];					//0x102
	WCHAR	sMonGrouping[11];					//0x10C
	WCHAR	sPositiveSign[6];					//0x122
	WCHAR	sNegativeSign[6];					//0x12E
	WCHAR	sTimeFormat[MAX_REG_VAL_SIZE + 1];	//0x13A
	WCHAR	sShortTime[MAX_REG_VAL_SIZE + 1];	//0x1DC
	WCHAR	s1159[16];							//0x27E
	WCHAR	s2359[16];							//0x29E
	WCHAR	sShortDate[MAX_REG_VAL_SIZE + 1];	//0x2BE
	WCHAR	sYearMonth[MAX_REG_VAL_SIZE + 1];	//0x360
	WCHAR	sLongDate[MAX_REG_VAL_SIZE + 1];	//0x402

	WCHAR	iCountry;							//0x4A4
	WCHAR	iMeasure;							//0x4A6
	WCHAR	iPaperSize;							//0x4A8
	WCHAR	iDigits;							//0x4AA
	WCHAR	iLZero;								//0x4AC
	WCHAR	iNegNumber;							//0x4AE
	WCHAR	NumShape;							//0x4B0
	WCHAR	iCurrDigits;						//0x4B2
	WCHAR	iCurrency;							//0x4B4
	WCHAR	iNegCurr;							//0x4B6
	WCHAR	iFirstDayOfWeek;					//0x4B8
	WCHAR	iFirstWeekOfYear;					//0x4BA [30]

	WCHAR	sCurrency[14];						//0x4BC
	WCHAR	iCalendarType;						//0x4D8
	// ExplicitSettings
	WCHAR	Currencies[5];						//0x4DA
	WCHAR	ShortDate[MAX_REG_VAL_SIZE + 1];	//0x4E4
	WCHAR	LongDate[MAX_REG_VAL_SIZE + 1];		//0x586

	BOOL	fCacheValid;						//0x628 ULONG NlsCacheUpdated
	LUID	InteractiveUserLuid;				//0x62C TokenStatistics.AuthenticationId
	SE_SID	InteractiveUserSid;					//0x634 SECURITY_MAX_SID_SIZE 68 = 0x44
	ULONG	ulCacheUpdateCount;					//0x678 basesrv.dll!BaseSrvNlsGetUserInfo
} NLS_USER_INFO, * PNLS_USER_INFO;				//0x67C = 1660

// win 10 20H1++ basesrv.dll!ServerDllInitialization
// Credit: https://gist.github.com/Auscitte/ed807fd604d7b907ebd949628c6df725 [Auscitte]
typedef struct _BASE_STATIC_SERVER_DATA
{
	UNICODE_STRING WindowsDirectory;							//0x0
	UNICODE_STRING WindowsSystemDirectory;						//0x10
	UNICODE_STRING NamedObjectDirectory;						//0x20
	USHORT WindowsMajorVersion;									//0x30
	USHORT WindowsMinorVersion;									//0x32
	USHORT BuildNumber;											//0x34
	USHORT CSDNumber;											//0x36
	USHORT RCNumber;											//0x38
	WCHAR CSDVersion[128];										//0x3A
	//SYSTEM_BASIC_INFORMATION SysInfo;							
	SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;						//0x140 (0x13A)
	PINIFILE_MAPPING IniFileMapping;							//0x170
	NLS_USER_INFO NlsUserInfo;									//0x178 kernelbase.dll!BaseNlsDllInitialize basesrv.dll!BaseSrvNlsGetUserInfo
	BOOLEAN DefaultSeparateVDM;									//0x7F4 kernelbase.dll!CreateProcessInternalW 
	BOOLEAN IsWowTaskReady;										//0x7F5
	UNICODE_STRING WindowsSys32x86Directory;					//0x7F8
	BOOLEAN fTermsrvAppInstallMode;								//0x808								
	DYNAMIC_TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;		//0x80C CsrBroadcastSystemMessageExW? tziDynamicTermsrvClientTimeZone TIME_ZONE_INFORMATION
	KSYSTEM_TIME ktTermsrvClientBias;							//0x9BC
	ULONG TermsrvClientTimeZoneId;								//0x9C8 kernelbase.dll!GetDynamicTimeZoneInformationCacheForYear
	BOOLEAN LUIDDeviceMapsEnabled;								//0x9CC kernelbase.dll!QueryDosDeviceW/DefineDosDeviceW->LUIDDeviceMapsEnabled
	ULONG TermsrvClientTimeZoneChangeNum;						//0x9D0 kernelbase.dll!GetClientTimeZoneInformation
	UNICODE_STRING AppContainerNamedObjectsDirectory;			//0x9D8 kernelbase.dll!BasepGetNamedObjectDirectoryForToken
	struct _BASE_STATIC_SERVER_DATA* RemoteBaseAddress;			//0x9E8 ++
	UNICODE_STRING PrivateNameObjectsDirectory;					//0x9F0 kernelbase.dll!BasepGetNamedObjectDirectoryForToken PrivateNamespace
} BASE_STATIC_SERVER_DATA, * PBASE_STATIC_SERVER_DATA;			//0xA00

#define BASE_SHARED_SERVER_DATA ((PBASE_STATIC_SERVER_DATA)( \
		(ULONGLONG)NtCurrentPeb()->ReadOnlySharedMemoryBase \
		+ (ULONGLONG)NtCurrentPeb()->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX] \
		- NtCurrentPeb()->CsrServerReadOnlySharedMemoryBase \
		))

#define MAX_SESSION_PATH  256
#define SESSION_ROOT L"\\Sessions"