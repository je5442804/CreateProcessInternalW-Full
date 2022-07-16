#pragma once
#include "structs.hpp"
#include <appmodel.h>

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
#define BASE_MSG_SXS_PACKAGE_IDENTITY_PRESENT                           (0x0400) // rev
#define BASE_MSG_SXS_FULL_TRUST_INTEGRITY_PRESENT                       (0x0800) // rev

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

typedef struct _BASE_MSG_SXS_STREAM {
    UCHAR          FileType;
    UCHAR          PathType;
    UCHAR          HandleType;//2
    UNICODE_STRING Path;//8
    HANDLE         FileHandle;//
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
            BYTE Reserved3[16];//96->112
            BYTE Reserved4[8];//112->120
            //====================================================
        };//Vista new Alternative
        struct
        {
            BASE_MSG_SXS_STREAM Manifest;//8
            BASE_MSG_SXS_STREAM Policy;//64
        }; //SafeMode old Classic
    };
    UNICODE_STRING AssemblyDirectory;//120->136
    //=================================================================
    UNICODE_STRING CacheSxsLanguageBuffer; //136->152 ===== [17]-[18]
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActivationContextRunLevel;//[19]-[20]/2   152->164 
    USHORT SxsProcessorArchitecture;// [20] + 4 164->168 Uncorrected!!! ****Version?? UnkowAppcompat
    UNICODE_STRING AssemblyIdentity;    //168->184 L"-----------------------------------------------------------" [21]-[22] //Microsoft.Windows.Shell.notepad
    ULONGLONG SxsMaxVersionTested;//184->192 [23]
    WCHAR ApplicationUserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH];
    //312 NULL
} BASE_SXS_CREATEPROCESS_MSG, * PBASE_SXS_CREATEPROCESS_MSG; 

typedef struct _BASE_CREATE_PROCESS {
    HANDLE ProcessHandle;//0
    HANDLE ThreadHandle;//8
    CLIENT_ID ClientId;//16
    ULONG CreationFlags;//32
    ULONG VdmBinaryType;//36
    ULONG VdmTask;//40
    HANDLE hVDM;//48
    BASE_SXS_CREATEPROCESS_MSG Sxs;  //
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
        BASE_CREATEPROCESS_MSG BaseCreateProcess;//+8 64
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

/* 现在 160->目标504
typedef struct _BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG {
    IN ULONG               Flags;
    IN USHORT              ProcessorArchitecture;
    IN LANGID              LangId;
    IN BASE_MSG_SXS_STREAM Manifest;
    IN BASE_MSG_SXS_STREAM Policy;
    IN UNICODE_STRING      AssemblyDirectory;
    IN UNICODE_STRING      TextualAssemblyIdentity;
    //
    // Csrss writes a PVOID through this PVOID.
    // It assumes the PVOID to write is of native size;
    // for a while it was. Now, it often is not, so
    // we do some manual marshalling in base\win32\client\csrsxs.c
    // to make it right. We leave this as plain PVOID
    // instead of say PVOID* (as it was for a while) to
    // defeat the wow64 thunk generator.
    //
    // The thunks can be seen in
    // base\wow64\whbase\obj\ia64\whbase.c
    //
    PVOID                  ActivationContextData;
} BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG, * PBASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG;
typedef const BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG* PCBASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG;

typedef struct _BASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT {
    HANDLE               Section;
    const UNICODE_STRING ProcessorArchitectureString;
    const ULONG          ProcessorArchitecture;
} BASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT, * PBASE_SRV_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT;
*/
//18
typedef NTSTATUS(WINAPI* BasepConstructSxsCreateProcessMessage_)( 
    IN PUNICODE_STRING SxsNtExePath, //a1
    IN PUNICODE_STRING SxsWin32ExePath, //a2
    IN HANDLE FileHandle,//a3
    IN HANDLE ProcessHandle,//a4
    IN HANDLE SectionHandle,//a5
    IN HANDLE TokenHandle,//a6
    IN BOOL DevOverrideEnabled,
    IN BOOL AppCompatSxsSafeMode,//BOOLEAN<-BOOL?
    IN PVOID AppCompatSxsData,
    IN ULONG AppCompatSxsDataSize,
    IN BOOL NoActivationContext, // (SectionImageInfomation.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0 
    IN LPCWSTR AppXCurrentDirectory, 
    IN PPEB PebAddress,//(PPEB) PVOID ULONGLONG
    IN PVOID ManifestAddress,
    IN ULONG ManifestSize,
    IN OUT PULONG CurrentParameterFlags,//PVOID
    OUT PBASE_SXS_CREATEPROCESS_MSG SxsMessage,
    OUT PSXS_CREATEPROCESS_UTILITY SxsCreateProcessUtilityStruct
); 

typedef NTSTATUS(NTAPI* CsrCaptureMessageMultiUnicodeStringsInPlace_)(
    IN OUT PCSR_CAPTURE_BUFFER* InOutCaptureBuffer,
    IN ULONG                    NumberOfStringsToCapture,
    IN const PUNICODE_STRING* StringsToCapture
    );
typedef NTSTATUS(WINAPI* CsrClientCallServer_)(PCSR_API_MESSAGE ApiMessage, PCSR_CAPTURE_BUFFER  CaptureBuffer, ULONG ApiNumber, ULONG DataLength);
