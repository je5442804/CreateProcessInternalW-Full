#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#include <iostream>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

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

#define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION 0x1
#define PSM_ACTIVATION_TOKEN_SHARED_ENTITY 0x2
#define PSM_ACTIVATION_TOKEN_FULL_TRUST 0x4
#define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE 0x8
#define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP 0x10
#define BREAKAWAY_INHIBITED 0x20

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
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess

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

#define STARTF_HASSHELLDATA         0x400
#define IMAGE_FILE_MACHINE_HYBRID_X86        0x3A64  // Hybrid: x86
#define ProcThreadAttributeConsoleReference 10

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

// LUA elevation support
#define ELEVATION_FLAG_TOKEN_CHECKS       0x00000001
#define ELEVATION_FLAG_VIRTUALIZATION     0x00000002
#define ELEVATION_FLAG_SHORTCUT_REDIR     0x00000004
#define ELEVATION_FLAG_NO_SIGNATURE_CHECK 0x00000008


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
	PROC_THREAD_ATTRIBUTE Attributes[1];
} PROC_THREAD_ATTRIBUTE_LIST, * LPPROC_THREAD_ATTRIBUTE_LIST;

// private
#define EXTENDED_PROCESS_CREATION_FLAG_ELEVATION_HANDLED 0x00000001
#define EXTENDED_PROCESS_CREATION_FLAG_FORCELUA 0x00000002
#define EXTENDED_PROCESS_CREATION_FLAG_FORCE_BREAKAWAY 0x00000004 // requires SeTcbPrivilege // since WINBLUE

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
	RtlPathTypeDriveRelative,
	RtlPathTypeRooted,
	RtlPathTypeRelative,
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

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }

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
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, * PAPPHELPCACHESERVICECLASS;

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

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;



typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

typedef struct _FILE_ID_INFORMATION
{
	ULONGLONG VolumeSerialNumber;//0
	FILE_ID_128 FileId;//8 GUID -> 16
} FILE_ID_INFORMATION, * PFILE_ID_INFORMATION;//24

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1, // FILE_DIRECTORY_INFORMATION
	FileFullDirectoryInformation, // FILE_FULL_DIR_INFORMATION
	FileBothDirectoryInformation, // FILE_BOTH_DIR_INFORMATION
	FileBasicInformation, // FILE_BASIC_INFORMATION
	FileStandardInformation, // FILE_STANDARD_INFORMATION
	FileInternalInformation, // FILE_INTERNAL_INFORMATION
	FileEaInformation, // FILE_EA_INFORMATION
	FileAccessInformation, // FILE_ACCESS_INFORMATION
	FileNameInformation, // FILE_NAME_INFORMATION
	FileRenameInformation, // FILE_RENAME_INFORMATION // 10
	FileLinkInformation, // FILE_LINK_INFORMATION
	FileNamesInformation, // FILE_NAMES_INFORMATION
	FileDispositionInformation, // FILE_DISPOSITION_INFORMATION
	FilePositionInformation, // FILE_POSITION_INFORMATION
	FileFullEaInformation, // FILE_FULL_EA_INFORMATION
	FileModeInformation, // FILE_MODE_INFORMATION
	FileAlignmentInformation, // FILE_ALIGNMENT_INFORMATION
	FileAllInformation, // FILE_ALL_INFORMATION
	FileAllocationInformation, // FILE_ALLOCATION_INFORMATION
	FileEndOfFileInformation, // FILE_END_OF_FILE_INFORMATION // 20
	FileAlternateNameInformation, // FILE_NAME_INFORMATION
	FileStreamInformation, // FILE_STREAM_INFORMATION
	FilePipeInformation, // FILE_PIPE_INFORMATION
	FilePipeLocalInformation, // FILE_PIPE_LOCAL_INFORMATION
	FilePipeRemoteInformation, // FILE_PIPE_REMOTE_INFORMATION
	FileMailslotQueryInformation, // FILE_MAILSLOT_QUERY_INFORMATION
	FileMailslotSetInformation, // FILE_MAILSLOT_SET_INFORMATION
	FileCompressionInformation, // FILE_COMPRESSION_INFORMATION
	FileObjectIdInformation, // FILE_OBJECTID_INFORMATION
	FileCompletionInformation, // FILE_COMPLETION_INFORMATION // 30
	FileMoveClusterInformation, // FILE_MOVE_CLUSTER_INFORMATION
	FileQuotaInformation, // FILE_QUOTA_INFORMATION
	FileReparsePointInformation, // FILE_REPARSE_POINT_INFORMATION
	FileNetworkOpenInformation, // FILE_NETWORK_OPEN_INFORMATION
	FileAttributeTagInformation, // FILE_ATTRIBUTE_TAG_INFORMATION
	FileTrackingInformation, // FILE_TRACKING_INFORMATION
	FileIdBothDirectoryInformation, // FILE_ID_BOTH_DIR_INFORMATION
	FileIdFullDirectoryInformation, // FILE_ID_FULL_DIR_INFORMATION
	FileValidDataLengthInformation, // FILE_VALID_DATA_LENGTH_INFORMATION
	FileShortNameInformation, // FILE_NAME_INFORMATION // 40
	FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
	FileIoStatusBlockRangeInformation, // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
	FileIoPriorityHintInformation, // FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX
	FileSfioReserveInformation, // FILE_SFIO_RESERVE_INFORMATION
	FileSfioVolumeInformation, // FILE_SFIO_VOLUME_INFORMATION
	FileHardLinkInformation, // FILE_LINKS_INFORMATION
	FileProcessIdsUsingFileInformation, // FILE_PROCESS_IDS_USING_FILE_INFORMATION
	FileNormalizedNameInformation, // FILE_NAME_INFORMATION
	FileNetworkPhysicalNameInformation, // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
	FileIdGlobalTxDirectoryInformation, // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
	FileIsRemoteDeviceInformation, // FILE_IS_REMOTE_DEVICE_INFORMATION
	FileUnusedInformation,
	FileNumaNodeInformation, // FILE_NUMA_NODE_INFORMATION
	FileStandardLinkInformation, // FILE_STANDARD_LINK_INFORMATION
	FileRemoteProtocolInformation, // FILE_REMOTE_PROTOCOL_INFORMATION
	FileRenameInformationBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
	FileLinkInformationBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION
	FileVolumeNameInformation, // FILE_VOLUME_NAME_INFORMATION
	FileIdInformation, // FILE_ID_INFORMATION
	FileIdExtdDirectoryInformation, // FILE_ID_EXTD_DIR_INFORMATION // 60
	FileReplaceCompletionInformation, // FILE_COMPLETION_INFORMATION // since WINBLUE
	FileHardLinkFullIdInformation, // FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
	FileIdExtdBothDirectoryInformation, // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
	FileDispositionInformationEx, // FILE_DISPOSITION_INFO_EX // since REDSTONE
	FileRenameInformationEx, // FILE_RENAME_INFORMATION_EX
	FileRenameInformationExBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION_EX
	FileDesiredStorageClassInformation, // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
	FileStatInformation, // FILE_STAT_INFORMATION
	FileMemoryPartitionInformation, // FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
	FileStatLxInformation, // FILE_STAT_LX_INFORMATION // since REDSTONE4 // 70
	FileCaseSensitiveInformation, // FILE_CASE_SENSITIVE_INFORMATION
	FileLinkInformationEx, // FILE_LINK_INFORMATION_EX // since REDSTONE5
	FileLinkInformationExBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION_EX
	FileStorageReserveIdInformation, // FILE_SET_STORAGE_RESERVE_ID_INFORMATION
	FileCaseSensitiveInformationForceAccessCheck, // FILE_CASE_SENSITIVE_INFORMATION
	FileKnownFolderInformation, // FILE_KNOWN_FOLDER_INFORMATION // since WIN11
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
	//56
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

	PVOID PackageDependencyData; //0x400
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName; // REDSTONE4
	UNICODE_STRING HeapPartitionName; // 19H1
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
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
} RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;

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
//define RTL_USER_PROC_USE_DOTLOCAL 0x00008000 uncorrected
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000


// private
#define PROTECTION_LEVEL_WINTCB_LIGHT 0x00000000
#define PROTECTION_LEVEL_WINDOWS 0x00000001
#define PROTECTION_LEVEL_WINDOWS_LIGHT 0x00000002
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT 0x00000003
#define PROTECTION_LEVEL_LSA_LIGHT 0x00000004
#define PROTECTION_LEVEL_WINTCB 0x00000005
#define PROTECTION_LEVEL_CODEGEN_LIGHT 0x00000006
#define PROTECTION_LEVEL_AUTHENTICODE 0x00000007

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

typedef struct _PROC_THREAD_BNOISOLATION_ATTRIBUTE
{
	BOOL IsolationEnabled;
	WCHAR IsolationPrefix[0x88];
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
	PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
	PsAttributeJobList, // in HANDLE[]
	PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
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
	PS_ATTRIBUTE Attributes[30];			/// Depends on how many attribute entries should be supplied to NtCreateUserProcess
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
	LdrHotPatchAppliedReverse,
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
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
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

	PVOID GdiSharedHandleTable;
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
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

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
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
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

	WOW64_POINTER(PVOID) ActivationContextData;
	WOW64_POINTER(PVOID) ProcessAssemblyStorageMap;
	WOW64_POINTER(PVOID) SystemDefaultActivationContextData;
	WOW64_POINTER(PVOID) SystemAssemblyStorageMap;

	WOW64_POINTER(SIZE_T) MinimumStackCommit;

	WOW64_POINTER(PVOID) SparePointers[4];
	ULONG SpareUlongs[5];
	//WOW64_POINTER(PVOID *) FlsCallback;
	//LIST_ENTRY32 FlsListHead;
	//WOW64_POINTER(PVOID) FlsBitmap;
	//ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	//ULONG FlsHighIndex;

	WOW64_POINTER(PVOID) WerRegistrationData;
	WOW64_POINTER(PVOID) WerShipAssertPtr;
	WOW64_POINTER(PVOID) pContextData;
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
	KAFFINITY  AffinityMask;//  ULONG_PTR
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
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

typedef enum _AppModelPolicy_Type {
	LifecycleManager = 0x1,
	AppDataAccess = 0x2,
	WindowingModel = 0x3,
	DllSearchOrder = 0x4,
	Fusion = 0x5,
	NonWindowsCodeLoading = 0x6,
	ProcessEnd = 0x7,
	BeginThreadInit = 0x8,
	DeveloperInformation = 0x9,
	CreateFileAccess = 0xA,
	ImplicitPackageBreakaway_Internal = 0xB,
	ProcessActivationShim = 0xC,
	AppKnownToStateRepository = 0xD,
	AudioManagement = 0xE,
	PackageMayContainPublicComRegistrations = 0xF,
	PackageMayContainPrivateComRegistrations = 0x10,
	LaunchCreateProcessExtensions = 0x11,
	ClrCompat = 0x12,
	LoaderIgnoreAlteredSearchForRelativePath = 0x13,
	ImplicitlyActivateClassicAAAServersAsIU = 0x14,
	ComClassicCatalog = 0x15,
	ComUnmarshaling = 0x16,
	ComAppLaunchPerfEnhancements = 0x17,
	ComSecurityInitialization = 0x18,
	RoInitializeSingleThreadedBehavior = 0x19,
	ComDefaultExceptionHandling = 0x1A,
	ComOopProxyAgility = 0x1B,
	AppServiceLifetime = 0x1C,
	WebPlatform = 0x1D,
	WinInetStoragePartitioning = 0x1E,
	IndexerProtocolHandlerHost = 0x1F,
	LoaderIncludeUserDirectories = 0x20,
	ConvertAppContainerToRestrictedAppContainer = 0x21,
	PackageMayContainPrivateMapiProvider = 0x22,
	AdminProcessPackageClaims = 0x23,
	RegistryRedirectionBehavior = 0x24,
	BypassCreateProcessAppxExtension = 0x25,
	KnownFolderRedirection = 0x26,
	PrivateActivateAsPackageWinrtClasses = 0x27,
	AppPrivateFolderRedirection = 0x28,
	GlobalSystemAppDataAccess = 0x29,
	ConsoleHandleInheritance = 0x2A,
	ConsoleBufferAccess = 0x2B,
	ConvertCallerTokenToUserTokenForDeployment = 0x2C,
	ShellExecuteRetrieveIdentityFromCurrentProcess = 0x2D, // Win 10 RS5+
	CodeIntegritySigning = 0x2E,                           // Win 10 19H1+
	PTCActivation = 0x2F,                                  // Win 10 19H1+
	COMIntraPackageRPCCall = 0x30,                         // Win 10 20H1+
	LoadUser32ShimOnWindowsCoreOS = 0x31,                  // Win 10 20H1+
	SecurityCapabilitiesOverride = 0x32,                   // Win 10 20H1+
	CurrentDirectoryOverride = 0x33,                       // Win 10 20H1+
	COMTokenMatchingForAAAServers = 0x34,                  // Win 10 20H1+
	UseOriginalFileNameInTokenFQBNAttribute = 0x35,        // Win 10 20H1+
	LoaderIncludeAlternateForwarders = 0x36,               // Win 10 20H1+
	PullPackageDependencyData = 0x37,                      // Win 10 20H1+
	AppInstancingErrorBehavior = 0x38,                     // Win 11+
	BackgroundTaskRegistrationType = 0x39,                 // Win 11+
	ModsPowerNotifification = 0x3A                         // Win 11+
} AppModelPolicy_Type;


typedef enum _AppModelPolicy_PolicyValue {
	None = 0,
	LifecycleManager_Unmanaged = 0x10000,//Win 10 RS1+
	LifecycleManager_ManagedByPLM = 0x10001,
	LifecycleManager_ManagedByEM = 0x10002,
	AppDataAccess_Allowed = 0x20000,
	AppDataAccess_Denied = 0x20001,
	WindowingModel_Hwnd = 0x30000,
	WindowingModel_CoreWindow = 0x30001,
	WindowingModel_LegacyPhone = 0x30002,
	WindowingModel_None = 0x30003,
	DllSearchOrder_Traditional = 0x40000,
	DllSearchOrder_PackageGraphBased = 0x40001,
	Fusion_Full = 0x50000,
	Fusion_Limited = 0x50001,
	NonWindowsCodeLoading_Allowed = 0x60000,
	NonWindowsCodeLoading_Denied = 0x60001,
	ProcessEnd_TerminateProcess = 0x70000,
	ProcessEnd_ExitProcess = 0x70001,
	BeginThreadInit_RoInitialize = 0x80000,
	BeginThreadInit_None = 0x80001,
	DeveloperInformation_UI = 0x90000,
	DeveloperInformation_None = 0x90001,
	CreateFileAccess_Full = 0xA0000,
	CreateFileAccess_Limited = 0xA0001,
	ImplicitPackageBreakaway_Allowed = 0xB0000,
	ImplicitPackageBreakaway_Denied = 0xB0001,
	ImplicitPackageBreakaway_DeniedByApp = 0xB0002,
	ProcessActivationShim_None = 0xC0000,
	ProcessActivationShim_PackagedCWALauncher = 0xC0001,
	AppKnownToStateRepository_Known = 0xD0000,
	AppKnownToStateRepository_Unknown = 0xD0001,
	AudioManagement_Unmanaged = 0xE0000,
	AudioManagement_ManagedByPBM = 0xE0001,
	PackageMayContainPublicComRegistrations_Yes = 0xF0000,
	PackageMayContainPublicComRegistrations_No = 0xF0001,
	PackageMayContainPrivateComRegistrations_None = 0x100000,
	PackageMayContainPrivateComRegistrations_PrivateHive = 0x100001,
	LaunchCreateProcessExtensions_None = 0x110000,
	LaunchCreateProcessExtensions_RegisterWithPsm = 0x110001,
	LaunchCreateProcessExtensions_RegisterWithDesktopAppX = 0x110002,
	ClrCompat_Others = 0x120000,
	ClrCompat_ClassicDesktop = 0x120001,
	ClrCompat_Universal = 0x120002,
	ClrCompat_PackagedDesktop = 0x120003,
	LoaderIgnoreAlteredSearchForRelativePath_False = 0x130000,
	LoaderIgnoreAlteredSearchForRelativePath_True = 0x130001,
	ImplicitlyActivateClassicAAAServersAsIU_Yes = 0x140000,
	ImplicitlyActivateClassicAAAServersAsIU_No = 0x140001,
	ComClassicCatalog_MachineHiveAndUserHive = 0x150000,
	ComClassicCatalog_MachineHiveOnly = 0x150001,
	ComUnmarshaling_ForceStrongUnmarshaling = 0x160000,
	ComUnmarshaling_ApplicationManaged = 0x160001,
	ComAppLaunchPerfEnhancements_Enabled = 0x170000,
	ComAppLaunchPerfEnhancements_Disabled = 0x170001,
	ComSecurityInitialization_ApplicationManaged = 0x180000,
	ComSecurityInitialization_SystemManaged = 0x180001,
	RoInitializeSingleThreadedBehavior_ASTA = 0x190000,
	RoInitializeSingleThreadedBehavior_STA = 0x190001,
	ComDefaultExceptionHandling_HandleAll = 0x1A0000,
	ComDefaultExceptionHandling_HandleNone = 0x1A0001,
	ComOopProxyAgility_Agile = 0x1B0000,
	ComOopProxyAgility_NonAgile = 0x1B0001,
	AppServiceLifetime_StandardTimeout = 0x1C0000,
	AppServiceLifetime_ExtendedForSamePackage = 0x1C0001,
	WebPlatform_Edge = 0x1D0000,
	WebPlatform_Legacy = 0x1D0001,
	WinInetStoragePartitioning_Isolated = 0x1E0000,
	WinInetStoragePartitioning_SharedWithAppContainer = 0x1E0001,
	IndexerProtocolHandlerHost_PerUser = 0x1F0000,//// Win 10 RS2+
	IndexerProtocolHandlerHost_PerApp = 0x1F0001,
	LoaderIncludeUserDirectories_False = 0x200000,
	LoaderIncludeUserDirectories_True = 0x200001,
	ConvertAppContainerToRestrictedAppContainer_False = 0x210000,
	ConvertAppContainerToRestrictedAppContainer_True = 0x210001,
	PackageMayContainPrivateMapiProvider_None = 0x220000,
	PackageMayContainPrivateMapiProvider_PrivateHive = 0x220001,
	AdminProcessPackageClaims_None = 0x230000,//Win 10 RS3+
	AdminProcessPackageClaims_Caller = 0x230001,
	RegistryRedirectionBehavior_None = 0x240000,
	RegistryRedirectionBehavior_CopyOnWrite = 0x240001,
	BypassCreateProcessAppxExtension_False = 0x250000,
	BypassCreateProcessAppxExtension_True = 0x250001,
	KnownFolderRedirection_Isolated = 0x260000,
	KnownFolderRedirection_RedirectToPackage = 0x260001,
	PrivateActivateAsPackageWinrtClasses_AllowNone = 0x270000,
	PrivateActivateAsPackageWinrtClasses_AllowFullTrust = 0x270001,
	PrivateActivateAsPackageWinrtClasses_AllowNonFullTrust = 0x270002,
	AppPrivateFolderRedirection_None = 0x280000,
	AppPrivateFolderRedirection_AppPrivate = 0x280001,
	GlobalSystemAppDataAccess_Normal = 0x290000,
	GlobalSystemAppDataAccess_Virtualized = 0x290001,
	ConsoleHandleInheritance_ConsoleOnly = 0x2A0000,//Win 10 RS4+
	ConsoleHandleInheritance_All = 0x2A0001,
	ConsoleBufferAccess_RestrictedUnidirectional = 0x2B0000,
	ConsoleBufferAccess_Unrestricted = 0x2B0001,
	ConvertCallerTokenToUserTokenForDeployment_UserCallerToken = 0x2C0000,
	ConvertCallerTokenToUserTokenForDeployment_ConvertTokenToUserToken = 0x2C0001,

	ShellExecuteRetrieveIdentityFromCurrentProcess_False = 0x2D0000, // Win 10 RS5+
	ShellExecuteRetrieveIdentityFromCurrentProcess_True = 0x2D0001,

	CodeIntegritySigning_Default = 0x2E0000,                           // Win 10 19H1+
	CodeIntegritySigning_OriginBased = 0x2E0001,
	CodeIntegritySigning_OriginBasedForDev = 0x2E0002,
	PTCActivation_Default = 0x2F0000,
	PTCActivation_AllowActivationInBrokerForMediumILContainer = 0x2F0001,

	COMIntraPackageRPCCall_NoWake = 0x300000,                         // Win 10 20H1+
	COMIntraPackageRPCCall_Wake = 0x300001,
	LoadUser32ShimOnWindowsCoreOS_True = 0x310000,
	LoadUser32ShimOnWindowsCoreOS_False = 0x310001,
	SecurityCapabilitiesOverride_None = 0x320000,
	SecurityCapabilitiesOverride_PackageCapabilities = 0x320001,
	CurrentDirectoryOverride_None = 0x330000,
	CurrentDirectoryOverride_PackageInstallDirectory = 0x330001,
	COMTokenMatchingForAAAServers_DontUseNtCompareTokens = 0x340000,
	COMTokenMatchingForAAAServers_UseNtCompareTokens = 0x340001,
	UseOriginalFileNameInTokenFQBNAttribute_False = 0x350000,
	UseOriginalFileNameInTokenFQBNAttribute_True = 0x350001,
	LoaderIncludeAlternateForwarders_False = 0x360001,
	LoaderIncludeAlternateForwarders_True = 0x360000,
	PullPackageDependencyData_False = 0x370000,
	PullPackageDependencyData_True = 0x370001,
	AppInstancingErrorBehavior_SuppressErrors = 0x380000,       // Win 11+
	AppInstancingErrorBehavior_RaiseErrors = 0x380001,
	BackgroundTaskRegistrationType_Unsupported = 0x390000,
	BackgroundTaskRegistrationType_Manifested = 0x390001,
	BackgroundTaskRegistrationType_Win32CLSID = 0x390002,
	ModsPowerNotifification_Disabled = 0x3A0000,
	ModsPowerNotifification_Enabled = 0x3A0001
} AppModelPolicy_PolicyValue, * PAppModelPolicy_PolicyValue;

typedef struct _PS_PKG_CLAIM {
	ULONG_PTR Flags;
	ULONG_PTR Origin;
} PS_PKG_CLAIM, * PPS_PKG_CLAIM;

typedef struct _CONSOLE_HANDLE_INFO {
	HANDLE ConsoleHandle;
	BOOLEAN ConsoleUnknow;
}CONSOLE_HANDLE_INFO, * PCONSOLE_HANDLE_INFO;

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
			USHORT Reversed : 16;
		}s1;
	};
	LPCWSTR AppXRedirectionDllName;//88
}APPX_PROCESS_CONTEXT, * PAPPX_PROCESS_CONTEXT;

typedef struct _DESKTOP_APPX_ACTIVATION_INFO
{
	BOOLEAN AppXActivate;
	HANDLE Semaphore;
}DESKTOP_APPX_ACTIVATION_INFO, * PDESKTOP_APPX_ACTIVATION_INFO;

//APP_EXECUTION_ALIAS_INFO_EXTEND
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

class ExtendedAppExecutionAliasInfo_New
{
public:

	//private:
	PWSTR AppXPackageName = NULL;//0 WCHAR [256]
	LPCWSTR AppAliasBaseImagePath = NULL;//8
	HANDLE TokenHandle = NULL;//16
	LPCWSTR BreakawayCommandeLine = NULL;//24
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


// STARTF_?? = 0x10000  (holographic/VR related ???) since win 10 1903 [18362]
// STARTF_HOLOLENAPPFASTMODE ??????
// https://learn.microsoft.com/en-us/hololens/hololens-release-notes [Microsoft Windows Hololens 2]
#define STARTF_HOLOLENAPPNOWAIT 0x00010000 //Fake define lol, Do NOT care about it [uncorrected]