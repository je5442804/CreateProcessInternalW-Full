#pragma once
#include "structs.hpp"

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2 // ?
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000 // dbg
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000 // dbg
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000 // dbg

#define BASE_MSG_SXS_MANIFEST_PRESENT                                   (0x0001)
#define BASE_MSG_SXS_POLICY_PRESENT                                     (0x0002)
#define BASE_MSG_SXS_SYSTEM_DEFAULT_TEXTUAL_ASSEMBLY_IDENTITY_PRESENT   (0x0004)
#define BASE_MSG_SXS_TEXTUAL_ASSEMBLY_IDENTITY_PRESENT                  (0x0008)
#define BASE_MSG_SXS_APP_RUNNING_IN_SAFEMODE                            (0x0010)
#define BASE_MSG_SXS_NO_ISOLATION                                       (0x0020) // rev
#define BASE_MSG_SXS_ALTERNATIVE_MODE                                   (0x0040) // rev
#define BASE_MSG_SXS_DEV_OVERRIDE_PRESENT                               (0x0080) // rev
#define BASE_MSG_SXS_MANIFEST_OVERRIDE_PRESENT                          (0x0100) // rev
#define BASE_MSG_SXS_DOTLOCAL_OVERRIDE_PRESENT                          (0x0200) // uncorrected
#define BASE_MSG_SXS_PACKAGE_IDENTITY_PRESENT                           (0x0400) // rev
#define BASE_MSG_SXS_FULL_TRUST_INTEGRITY_PRESENT                       (0x0800) // rev

#define SXS_APPCOMPACT_FLAG_APP_RUNNING_SAFEMODE                        (0x0001)

#define BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_FEEDBACK_ON                1
#define BASE_CREATE_PROCESS_MSG_PROCESS_FLAG_GUI_WAIT                   2
#define BASE_CREATE_PROCESS_MSG_THREAD_FLAG_CROSS_SESSION               1
#define BASE_CREATE_PROCESS_MSG_THREAD_FLAG_PROTECTED_PROCESS           2

typedef ULONG CSR_API_NUMBER;
#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
    (CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSR_APINUMBER_TO_SERVERDLLINDEX( ApiNumber ) \
    ((ULONG)((ULONG)(ApiNumber) >> 16))

#define CSR_APINUMBER_TO_APITABLEINDEX( ApiNumber ) \
    ((ULONG)((USHORT)(ApiNumber)))

typedef struct _BASESRV_API_CONNECTINFO {
    IN ULONG ExpectedVersion;
    OUT HANDLE DefaultObjectDirectory;
    OUT ULONG WindowsVersion;
    OUT ULONG CurrentVersion;
    OUT ULONG DebugFlags;
    OUT WCHAR WindowsDirectory[MAX_PATH];
    OUT WCHAR WindowsSystemDirectory[MAX_PATH];
} BASESRV_API_CONNECTINFO, * PBASESRV_API_CONNECTINFO;

#define BASESRV_VERSION 0x10000
//
// Message format for messages sent from the client to the server
//
//Ntapi.ntcsrapi.pas
typedef enum _BASESRV_API_NUMBER {
    BasepCreateProcess = BASESRV_FIRST_API_NUMBER,             // in: TBaseCreateProcessMsgV1
    BasepDeadEntry1,
    BasepDeadEntry2,
    BasepDeadEntry3,
    BasepDeadEntry4,
    BasepCheckVDM,
    BasepUpdateVDMEntry,
    BasepGetNextVDMCommand,
    BasepExitVDM,
    BasepIsFirstVDM,
    BasepGetVDMExitCode,
    BasepSetReenterCount,
    BasepSetProcessShutdownParam,   // in: TBaseShutdownParamMsg
    BasepGetProcessShutdownParam,   // out: TBaseShutdownParamMsg
    BasepSetVDMCurDirs,
    BasepGetVDMCurDirs,
    BasepBatNotification,
    BasepRegisterWowExec,
    BasepSoundSentryNotification,
    BasepRefreshIniFileMapping,
    BasepDefineDosDevice,          // in: TBaseDefineDosDeviceMsg
    BasepSetTermsrvAppInstallMode,
    BasepSetTermsrvClientTimeZone,
    BasepCreateActivationContext,  // in/out: TBaseSxsCreateActivationContextMsg
    BasepDeadEntry24,
    BasepRegisterThread,
    BasepDeferredCreateProcess,
    BasepNlsGetUserInfo,
    BasepNlsUpdateCacheCount,
    BasepCreateProcess2,           // in: TBaseCreateProcessMsgV2, Win 10 20H1+
    BasepCreateActivationContext2  // in/out: TBaseSxsCreateActivationContextMsgV2, Win 10 20H1+
} BASESRV_API_NUMBER, * PBASESRV_API_NUMBER;

#define PORT_CONNECT 0x0001
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

typedef struct _CSR_API_CONNECTINFO {
    PVOID SharedSectionBase;
    PVOID SharedStaticServerData;
    PVOID ServerProcessId;
    PVOID Reserved;//8 bytes
    DWORD Reserved2;//4 bytes
    DWORD Reserved3;//4 bytes
    PVOID Reserved4;//8 bytes
} CSR_API_CONNECTINFO, * PCSR_API_CONNECTINFO; //0x30

typedef struct _CSR_CLIENTCONNECT_MSG {
    ULONG ServerDllIndex;
    PVOID ConnectionInformation;
    ULONG ConnectionInformationLength;
} CSR_CLIENTCONNECT_MSG, * PCSR_CLIENTCONNECT_MSG;

typedef struct _CSR_CAPTURE_BUFFER {
    ULONG Length;//0         0x184 = 388
    PVOID RelatedCaptureBuffer;//8            PCSR_CAPTURE_HEADER 0x baadf00d baadf00d = 0xbaadf00dbaadf00d
    ULONG CountMessagePointers; //16
    PCHAR FreeSpace;//24
    ULONG_PTR MessagePointerOffsets[1];//32  // Offsets within CSR_API_MSG of pointers ->previously as pointer at 0x10 [ANYSIZE_ARRAY]
} CSR_CAPTURE_BUFFER, * PCSR_CAPTURE_BUFFER;

typedef struct _CSR_API_MESSAGE {
    PORT_MESSAGE h;
    union {
        CSR_API_CONNECTINFO ConnectionRequest;
        struct {
            PCSR_CAPTURE_BUFFER CaptureBuffer;
            CSR_API_NUMBER ApiNumber;
            ULONG ReturnValue;
            ULONG Reserved;
            union {
                CSR_CLIENTCONNECT_MSG ClientConnect;
                ULONG_PTR ApiMessageData[0x2E];// 6.2+ 
            } u;
        };
    };
} CSR_API_MESSAGE, * PCSR_API_MESSAGE;


typedef struct _SXS_CONSTANT_WIN32_NT_PATH_PAIR
{
    PCUNICODE_STRING Win32;
    PCUNICODE_STRING Nt;
} SXS_CONSTANT_WIN32_NT_PATH_PAIR;
typedef       SXS_CONSTANT_WIN32_NT_PATH_PAIR* PSXS_CONSTANT_WIN32_NT_PATH_PAIR;
typedef const SXS_CONSTANT_WIN32_NT_PATH_PAIR* PCSXS_CONSTANT_WIN32_NT_PATH_PAIR;

typedef struct _SXS_WIN32_NT_PATH_PAIR
{
    PUNICODE_STRING   Win32;
    PUNICODE_STRING   Nt;
} SXS_WIN32_NT_PATH_PAIR;
typedef       SXS_WIN32_NT_PATH_PAIR* PSXS_WIN32_NT_PATH_PAIR;
typedef const SXS_WIN32_NT_PATH_PAIR* PCSXS_WIN32_NT_PATH_PAIR;

#define BASE_MSG_FILETYPE_NONE             (0)
#define BASE_MSG_FILETYPE_XML              (1)
#define BASE_MSG_FILETYPE_PRECOMPILED_XML  (2)

#define BASE_MSG_PATHTYPE_NONE             (0)
#define BASE_MSG_PATHTYPE_FILE             (1)
#define BASE_MSG_PATHTYPE_URL              (2)
#define BASE_MSG_PATHTYPE_OVERRIDE         (3)

#define BASE_MSG_HANDLETYPE_NONE           (0)
#define BASE_MSG_HANDLETYPE_PROCESS        (1)
#define BASE_MSG_HANDLETYPE_CLIENT_PROCESS (2)
#define BASE_MSG_HANDLETYPE_SECTION        (3)

typedef struct _BASE_MSG_SXS_STREAM {
    UCHAR          FileType;        // BASE_MSG_FILETYPE_
    UCHAR          PathType;        // BASE_MSG_PATHTYPE_
    UCHAR          HandleType;      // BASE_MSG_HANDLETYPE_*
    UNICODE_STRING Path;
    HANDLE         FileHandle;
    HANDLE         Handle;
    ULONGLONG      Offset; // big enough to hold file offsets in the future
    SIZE_T         Size;
} BASE_MSG_SXS_STREAM, * PBASE_MSG_SXS_STREAM;
typedef const BASE_MSG_SXS_STREAM* PCBASE_MSG_SXS_STREAM;

typedef struct _SXS_OVERRIDE_STREAM {
    UNICODE_STRING Name;
    //Length = 0
    //MaximumLength = 2
    //Buffer = 8
    PVOID          Address;//16
    SIZE_T         Size;//24
} SXS_OVERRIDE_STREAM, * PSXS_OVERRIDE_STREAM;//sizeof = 32
typedef const SXS_OVERRIDE_STREAM* PCSXS_OVERRIDE_STREAM;

typedef struct _BASE_SXS_CREATEPROCESS_MSG {//win 10 new
    ULONG   Flags; //0
    ULONG   ProcessParameterFlags;//4
    //=====================================================
    union 
    {
        struct
        {
            HANDLE FileHandle;//8
            UNICODE_STRING Win32ImagePath;//16
            UNICODE_STRING NtImagePath;//32;
            PVOID ManifestOverrideOffset;//48 AppCompatSxsData
            SIZE_T ManifestOverrideSize;//56 AppCompatSxsDataSize
            //============================
            PVOID PolicyOverrideOffset;//64
            SIZE_T PolicyOverrideSize;//72 Path???
            PVOID ManifestAddress;//80
            ULONG ManifestSize;//88
            //BYTE Reserved3[16];//96->112
            //BYTE Reserved4[8];//112->120
        };//Vista new Alternative
        struct
        {
            BASE_MSG_SXS_STREAM Manifest;//8
            BASE_MSG_SXS_STREAM Policy;//64
            UNICODE_STRING AssemblyDirectory;//120->136
        }; //SafeMode old Classic
    };
    //=================================================================
    UNICODE_STRING CultureFallBacks; //136->152 ===== [17]-[18] CultureFallBacks CacheSxsLanguageBuffer
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel;//[19]-[20]/2   152->164 
    SUPPORTED_OS_INFO SxsSupportOSInfo;// [20] + 4 164->168 [SwitchBackSupportOSInfo]
    UNICODE_STRING AssemblyName;    //168->184 L"-----------------------------------------------------------" [21]-[22] //Microsoft.Windows.Shell.notepad
    ULONGLONG SxsMaxVersionTested;//184->192 [23]
    WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];//192
    ULONG ApplicationUserModelIdLength;//452
} BASE_SXS_CREATEPROCESS_MSG, * PBASE_SXS_CREATEPROCESS_MSG; //0x1C8 = 456

typedef struct _BASE_CREATE_PROCESS {
    HANDLE ProcessHandle;//0
    HANDLE ThreadHandle;//8
    CLIENT_ID ClientId;//16
    ULONG CreationFlags;//32
    ULONG VdmBinaryType;//36
    ULONG VdmTask;//40
    HANDLE hVDM;//48
    BASE_SXS_CREATEPROCESS_MSG Sxs;  //56
    ULONGLONG PebAddressNative; //
    ULONGLONG PebAddressWow64;//
    USHORT ProcessorArchitecture;
} BASE_CREATEPROCESS_MSG, *PBASE_CREATEPROCESS_MSG; //536

//64+56=120
typedef struct _BASE_API_MSG
{
    PORT_MESSAGE          PortMessage;//0
    PCSR_CAPTURE_BUFFER   CaptureBuffer;//40
    CSR_API_NUMBER        ApiNumber;//48
    ULONG                 Status;//52
    ULONG                 Reserved;//56
    union
    {
        //BASE_CREATETHREAD_MSG  BaseCreateThread;
        BASE_CREATEPROCESS_MSG BaseCreateProcess;//64
    }u;
}BASE_API_MSG, * PBASE_API_MSG;

typedef struct _BASE_MSG_SXS_HANDLES {
    HANDLE File;
    //
    // Process is the process to map section into, it can
    // be NtCurrentProcess; ensure that case is optimized.
    //
    HANDLE Process;
    HANDLE Section;
    PVOID ViewBase; // Don't use this is in 32bit code on 64bit. This is ImageBaseAddress
} BASE_MSG_SXS_HANDLES, * PBASE_MSG_SXS_HANDLES; 

typedef struct _SXS_CREATEPROCESS_UTILITY { 
    BASE_MSG_SXS_HANDLES ManifestHandles;
    BASE_MSG_SXS_HANDLES PolicyHandles;
    PUNICODE_STRING SxsStringBuffers;//Heap1
    PUNICODE_STRING ReservedStringsBuffers;//Heap2
    HANDLE FileHandle;//AppXFileHandle
}SXS_CREATEPROCESS_UTILITY,*PSXS_CREATEPROCESS_UTILITY; //88

typedef struct _SXS_GENERATE_ACTIVATION_CONTEXT_STREAM
{
    IStream* Stream;

    //
    // This is not necessarily a file system path, just something
    // for descriptive/debugging purposes.
    //
    // Still, when they are file system paths, we try to keep them as Win32 paths instead of Nt paths.
    //
    PCWSTR  Path;
    ULONG   PathType;
} SXS_GENERATE_ACTIVATION_CONTEXT_STREAM;


// 104 -> 408 OK SxsGenerateActivationContextParameters
typedef struct _SXS_GENERATE_ACTIVATION_CONTEXT_PARAMETERS
{
    IN DWORD                    Flags;//0
    IN USHORT                   ProcessorArchitecture;//4
    IN PWSTR                    CultureFallBacks;//8
    IN PCWSTR                   AssemblyDirectory; //16 should be a Win32 path
    IN PCWSTR                   TextualAssemblyIdentity;//24

    IN SXS_GENERATE_ACTIVATION_CONTEXT_STREAM Manifest;//32
    IN SXS_GENERATE_ACTIVATION_CONTEXT_STREAM Policy;//56
    IN ULONGLONG                ResourceId;//80
    // when generate activation context for system default fails, 
    // this mask shows whether it fails for some certain reason which we could ignore the error.
    OUT DWORD                   SystemDefaultActCxtGenerationResult; //88
    OUT HANDLE                  SectionObjectHandle;//96

    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel;//104
    DWORD SxsSupportedOSMajorVersion; //116
    //PSXS_IMPERSONATION_CALLBACK ImpersonationCallback;
    //PVOID                       ImpersonationContext;
    OUT ULONGLONG               SxsMaxVersionTested;//120
    WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];//128 
    ULONG ApplicationUserModelIdLength;//??? APPLICATION_USER_MODEL_ID_MAX_LENGTH + 2 ?

    PCWSTR AssemblyName;//392
    USHORT AssemblyNameLength;
} SXS_GENERATE_ACTIVATION_CONTEXT_PARAMETERS, * PSXS_GENERATE_ACTIVATION_CONTEXT_PARAMETERS;
typedef const SXS_GENERATE_ACTIVATION_CONTEXT_PARAMETERS* PCSXS_GENERATE_ACTIVATION_CONTEXT_PARAMETERS;

 //现在 160->目标504 OK!
typedef struct _BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG {
    ULONG                   Flags;//0
    USHORT                  ProcessorArchitecture;//4
    UNICODE_STRING          CultureFallBacks;//8
    BASE_MSG_SXS_STREAM     Manifest;//24
    BASE_MSG_SXS_STREAM     Policy;//80
    UNICODE_STRING          AssemblyDirectory;//136
    UNICODE_STRING          TextuaNAssemblyIdentity;//152
    LARGE_INTEGER           FileLastWriteTime;//168
    ULONGLONG               ResourceId;//176  == 1 ??
    PVOID                   ActivationContextData;//184
    PVOID                   ActivationContextDataWow64;//192
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel;//200
    ULONG                   SxsSupportedOSMajorVersion;//212
    UNICODE_STRING          AssemblyName;//216
    ULONGLONG SxsMaxVersionTested;//232
    WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];//240
    ULONG ApplicationUserModelIdLength;
} BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG, * PBASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG;//504
typedef const BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG* PCBASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG;


typedef struct _BASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT {
    HANDLE               Section;
    const UNICODE_STRING ProcessorArchitectureString;
    const ULONG          ProcessorArchitecture;
} BASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT, * PBASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT;


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
    BOOLEAN IsWowTaskReady;										//0x7F5 basesrv.dll!ServerDllInitialization kernel32.dll!GetNextVDMCommand
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

//18
typedef NTSTATUS(WINAPI* BasepConstructSxsCreateProcessMessage_)( 
    IN PUNICODE_STRING SxsNtExePath, //a1
    IN PUNICODE_STRING SxsWin32ExePath, //a2
    IN HANDLE FileHandle,//a3
    IN HANDLE ProcessHandle,//a4
    IN HANDLE SectionHandle,//a5
    IN HANDLE TokenHandle,//a6
    IN BOOL DevOverrideEnabled,
    IN ULONG dwFusionFlags,
    IN PVOID AppCompatSxsData,
    IN ULONG AppCompatSxsDataSize,
    IN BOOL NoActivationContext, // (SectionImageInfomation.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0 
    IN LPCWSTR CurrentDirectory, 
    IN PPEB PebAddress,//(PPEB) PVOID ULONGLONG
    IN PVOID ManifestAddress,
    IN ULONG ManifestSize,
    IN OUT PULONG CurrentParameterFlags,//PVOID
    OUT PBASE_SXS_CREATEPROCESS_MSG SxsMessage,
    OUT PSXS_CREATEPROCESS_UTILITY SxsCreateProcessUtilityStruct
); 

EXTERN_C NTSYSAPI NTSTATUS NTAPI CsrCaptureMessageMultiUnicodeStringsInPlace(
    IN OUT PCSR_CAPTURE_BUFFER* InOutCaptureBuffer,
    IN ULONG                    NumberOfStringsToCapture,
    IN const PUNICODE_STRING* StringsToCapture
    );
EXTERN_C NTSYSAPI NTSTATUS NTAPI CsrClientCallServer(PCSR_API_MESSAGE ApiMessage, PCSR_CAPTURE_BUFFER  CaptureBuffer, ULONG ApiNumber, ULONG DataLength);
EXTERN_C NTSYSAPI VOID NTAPI CsrFreeCaptureBuffer(PCSR_CAPTURE_BUFFER CaptureBuffer);