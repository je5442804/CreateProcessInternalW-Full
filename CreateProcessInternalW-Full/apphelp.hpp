#pragma once
#include "structs.hpp"

#ifndef _APPHELP_HEADER
#define _APPHELP_HEADER

typedef WCHAR* PWSZ;

typedef WORD TAG;
typedef DWORD TAGID;
typedef DWORD TAGREF;
typedef PVOID HSDB;

#define MAX_INDEXES             64
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

// uncorrected!
typedef struct _DB_FILE
{
	PVOID Buffer1;
	//----------------------------
	union
	{
		struct
		{
			HANDLE hFile;		//0x08
			HANDLE hSection;
			PVOID Reserved;
			PVOID lpBaseAddress;
		};
		struct
		{
			GUID uncorrected1;
			GUID uncorrected2;
			GUID uncorrected3;
		};
	};
	BOOLEAN bFile;//0x30
	BOOLEAN bSection;//0x31
	BOOLEAN bMemoryMapped;//0x32
	//---------------------------- RtlFileMapFree
	PVOID Buffer2;//0x40
	BOOL DisbaleFile;//0x48 true->FileHandle = NULL DisbaleCompress?
} DB_FILE, * PDB_FILE;


// Warning! 
// UNSTABLE MAX_INDEXES has been updated from 32 to 64 !!! 
// 
// ShimLog ShimDebug
// Require fixed aligment.
#ifndef _WIN64
#pragma pack(push, 4)
#else
#pragma pack(4)
#endif

//private
typedef struct _ASL_LOG_ENTRY
{
	UCHAR AslLogName[64];
	PVOID AslLogData;//64
	ULONG WrittenDataLength;//72
	ULONG AlignLength;//76 HeapAllocAlignBoundary MaxLengthPreCopy?  2的倍数? 0x400, 0x1000
	ULONG AppCompatLogFlags;//80 _ASL_LOG_LEVEL
	ULONG Reserved;//84
	ULONG EntryStateLock;//88
}ASL_LOG_ENTRY, * PASL_LOG_ENTRY;//92

// Restore previous aligment.
#ifdef _WIN64
#pragma pack()
#else
#pragma pack(pop)
#endif

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
}ASL_LOG, * PASL_LOG;

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

typedef void* HAPPHELPINFOCONTEXT;
typedef int(__fastcall* APPHELP_HOOK_COM)(wchar_t*, const _GUID*, const wchar_t*, const _GUID*, void**);
typedef enum SWITCH_CONTEXT_PLATFORM_ID {
	VISTA_ID = 0,
	WIN7_ID,
	WIN8_ID,
	WINBLUE_ID,
	WINTHRESHOLD_ID,
	MAX_SUPPORTED_PLATFORM_COUNT
} SWITCH_CONTEXT_PLATFORM_ID;

typedef enum SWITCH_CONTEXT_TYPE {
	STATIC_PROCESS_CONTEXT = 0,
	DYNAMIC_PROCESS_CONTEXT,
	MAX_CONTEXT_TYPE
} SWITCH_CONTEXT_TYPE;

typedef enum SWITCH_CONTEXT_SOURCE {
	SOURCE_UNKNOWN = 0,
	SOURCE_PE_SYSTEM,
	SOURCE_APPX_MANIFEST,
	SOURCE_UAC_MANIFEST,
	SOURCE_ENVIRONMENT,
	SOURCE_SHIM_OVERRIDE,
	SOURCE_DEFAULT
} SWITCH_CONTEXT_SOURCE;

typedef enum _SWITCH_CONTEXT_DLL_TRIGGER_CONDITION
{
	DLL_MAPPED,
	DLL_UNMAPPED
}SWITCH_CONTEXT_DLL_TRIGGER_CONDITION;

typedef enum tagAPPHELPINFORMATIONCLASS {
	ApphelpFlags = 0,
	ApphelpExeName,
	ApphelpAppName,
	ApphelpVendorName,
	ApphelpHtmlHelpID,
	ApphelpProblemSeverity,
	ApphelpLinkURL,
	ApphelpLinkText,
	ApphelpTitle,
	ApphelpDetails,
	ApphelpContact,
	ApphelpHelpCenterURL,
	ApphelpExeTagID,
	ApphelpDatabaseGUID
} APPHELPINFORMATIONCLASS;

typedef enum tagSDBMSILOOKUPSTATE {
	LOOKUP_NONE,
	LOOKUP_LOCAL,
	LOOKUP_CUSTOM,
	LOOKUP_MERGESTUB,
	LOOKUP_MAIN,
	LOOKUP_DONE
} SDBMSILOOKUPSTATE;

typedef enum _SDB_RUN_PLATFORM
{
	SDB_RUN_PLATFORM_X86,
	SDB_RUN_PLATFORM_AMD64,
	SDB_RUN_PLATFORM_X86_AMD64,
	SDB_RUN_PLATFORM_ARM32,
	SDB_RUN_PLATFORM_ARM64,
	SDB_RUN_PLATFORM_X86_ARM64,
	SDB_RUN_PLATFORM_ARM32_ARM64,
	SDB_RUN_PLATFORM_AMD64_ARM64,
	SDB_RUN_PLATFORM_MAX
}SDB_RUN_PLATFORM;

typedef enum _SDB_GUEST_PLATFORM
{
	SDB_GUEST_PLATFORM_X86,
	SDB_GUEST_PLATFORM_IA64,
	SDB_GUEST_PLATFORM_AMD64,
	SDB_GUEST_PLATFORM_ARM32,
	SDB_GUEST_PLATFORM_ARM64,
	SDB_GUEST_PLATFORM_MAX
}SDB_GUEST_PLATFORM;

typedef enum _SDB_UX_BLOCKTYPE_OVERRIDE {
	SDB_UX_BLOCKTYPE_OVERRIDE_NONE = 0,
	SDB_UX_BLOCKTYPE_OVERRIDE_NO_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_REINSTALL_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_SOFT_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_HARD_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_UPGRADE_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_MIG_FIXED,
	SDB_UX_BLOCKTYPE_OVERRIDE_MIG_REINSTALL,
	SDB_UX_BLOCKTYPE_OVERRIDE_MIG_REMOVED,
	SDB_UX_BLOCKTYPE_OVERRIDE_MIG_ASK_WER,
	SDB_UX_BLOCKTYPE_OVERRIDE_UPGRADE_CAN_REINSTALL_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_UPGRADE_UNTIL_UPDATE_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_REINSTALL_INFO_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_REINSTALL_WARN_BLOCK,
	SDB_UX_BLOCKTYPE_OVERRIDE_MAX
} SDB_UX_BLOCKTYPE_OVERRIDE;

typedef enum _SDB_MISSING_MATCHER_BEHAVIOR {
	SDB_MISSING_MATCHER_BEHAVIOR_UNDEFINED = 0,
	SDB_MISSING_MATCHER_BEHAVIOR_IGNORE,
	SDB_MISSING_MATCHER_BEHAVIOR_SUCCEED_MATCH,
	SDB_MISSING_MATCHER_BEHAVIOR_FAIL_MATCH,
	SDB_MISSING_MATCHER_BEHAVIOR_MAX_VALUE
} SDB_MISSING_MATCHER_BEHAVIOR;

typedef enum _SDB_CUSTOMDB_ENTRY_STATE {
	SDB_CUSTOMDB_ENTRY_STATE_UNKNOWN = 0,
	SDB_CUSTOMDB_ENTRY_STATE_ENABLED,
	SDB_CUSTOMDB_ENTRY_STATE_DISABLED,
	SDB_CUSTOMDB_ENTRY_STATE_NOT_FOUND
} SDB_CUSTOMDB_ENTRY_STATE;

typedef enum SDB_SYSTEM_DATABASE {
	SDB_SYSTEM_DATABASE_UNINITIALIZED = 0,
	SDB_SYSTEM_DATABASE_SYSTEM,
	SDB_SYSTEM_DATABASE_PCA,
	SDB_SYSTEM_DATABASE_DRIVER,
	SDB_SYSTEM_DATABASE_MSI,
	SDB_SYSTEM_DATABASE_FRAMEWORKS,
	SDB_SYSTEM_DATABASE_APPRAISER,
	SDB_SYSTEM_DATABASE_COUNT
} SDB_SYSTEM_DATABASE;

typedef enum _ZDB_COMPRESSION_ALGORITHM {
	ZDB_COMPRESSION_ALGORITHM_NONE = 0,
	ZDB_COMPRESSION_ALGORITHM_ZLIB125,
	ZDB_COMPRESSION_ALGORITHM_MAX_VALUE
} ZDB_COMPRESSION_ALGORITHM;

#define SHIMDB_MAGIC            0x66626473  // 'sdbf' (reversed because of little-endian ordering)
#define SHIMDB_COMPRESS_MAGIC   0x6662647A  // 'zdbf' (compressed magic)
#define SHIMDB_MAJOR_VERSION    3           // Don't change this unless fundamentals
// change (like TAG size, etc.)
#define SHIMDB_MINOR_VERSION    0           // This is for info only -- ignored on read

typedef enum _PATH_TYPE {
	DOS_PATH,
	NT_PATH
} PATH_TYPE;

typedef struct _DB_HEADER {
	DWORD       dwMajorVersion;
	DWORD       dwMinorVersion;
	DWORD       dwMagic;
} DB_HEADER, * PDB_HEADER;

typedef struct _ZDB_HEADER
{
	DB_HEADER SdbHeader;
	ZDB_COMPRESSION_ALGORITHM CompressionMethod;
	DWORD dwExpandedSize;
} ZDB_HEADER, * PZDB_HEADER;

//
// Warning! 
// UNSTABLE MAX_INDEXES has been updated from 32 to 64 !!!
//
typedef struct _DB {
	// used for both read and write
	PDB_FILE       UnknowSdbFileInfo;       // 0x000
	PVOID          pBase;                   // 0x008 for both memory-mapping & buffered writes
	BOOL           bWrite;                  // 0x010 was it opened with create?
	DWORD          dwSize;                  // 0x014 the size of the whole db, in bytes
	DWORD          dwFlags;                 // 0x018 flags (such as IN-memory flag)
	GUID           guidDB;                  // 0x020 optional id for the database
	INDEX_INFO     aIndexes[MAX_INDEXES];   // 0x030 data for the indexes, max indexs = 64 ? 32 ? 10
	ULONG          dwOldMajorVersion;       // 0xA30 wtf align to wchar_t Size btw use Flag bittest?

	PRTL_RUN_ONCE  lpScanIndexsOnce;        // 0xA38 have the indexes been looked at -> BOOL        bIndexesScanned; 
	PRTL_RUN_ONCE  lpStringTableOffset;     // 0xA40 InitOnceGetStringTableOffset

	TAGID          tiStringTable;           // 0xA48 pointer to the stringtable for string handling
	DWORD          dwIndexes;               // 0xA4C the number of indexes
	// stuff that's used for write? really?
	struct _DB*    pdbStringTable;          // 0xA50 stringtable is a subdatabase that's created on the side
	PVOID          pStringHash;             // 0xA58 stringtable hash (same info as in stringtable)
	DWORD          dwAllocatedSize;         // 0xA60 SdbpWriteBufferedData the size allocated for buffered writes
	BOOL           bWritingIndexes;         // 0xA64 are we in the process of allocating index space?
	TAGID          tiIndexes;               // 0xA68 used during index allocation
	UNICODE_STRING ustrTempStringtable;     // 0xA70 string table temp filename
} DB, * PDB;                                // 0xA80
// win 11 = 0xA80 
// win 10 21h1(19041.1023) = 0x580 ? 


typedef struct _APPHELP_INFO
{
	ULONG dwHtmlHelpID;
	DWORD dwSeverity;
	LPCWSTR lpszAppName;
	GUID guidID;
	ULONG tiExe;
	GUID guidDB;
	BOOL bOfflineContent;
	BOOL bUseHTMLHelp;
	LPCWSTR lpszChmFile;
	LPCWSTR lpszDetailsFile;
	BOOL bPreserveChoice;
	BOOL bMSI;
} APPHELP_INFO, * PAPPHELP_INFO;

typedef struct tagAPPHELP_DATA_EX
{
	GUID guidDBID;
	GUID guidExeID;
	GUID guidAppID;
	ULONG tiExe;
	DWORD dwFlags;
	DWORD dwSeverity;
	DWORD dwHTMLHelpID;
	LPCWSTR szAppName;
	LPCWSTR szVendorName;
	LPCWSTR szSummaryMsg;
	LPCWSTR szFullPath;
	LPCWSTR szLink;
	LPCWSTR szURL;
	DWORD dwFWLinkNumber;
	DWORD dwKBNumber;
	LPCWSTR szAppStoreId;
	DWORD dwDatabaseType;
} APPHELP_DATA_EX, * PAPPHELP_DATA_EX;

typedef struct _FIND_INFO {
	TAGID     tiIndex;
	TAGID     tiCurrent;
	TAGID     tiEndIndex;
	TAG       tName;
	DWORD     dwIndexRec;
	DWORD     dwFlags;
	ULONGLONG ullKey;
	union {
		LPCTSTR szName;
		DWORD   dwName;
		GUID* pguidName;
	};
} FIND_INFO, * PFIND_INFO;

typedef struct _SDB_CSTRUCT_COBALT_PROCFLAG {
	ULONGLONG AffinityMask;
	ULONG CPUIDEcxOverride;
	ULONG CPUIDEdxOverride;
	USHORT ProcessorGroup;
	USHORT FastSelfModThreshold;
	USHORT Reserved1;
	UCHAR Reserved2;
	UCHAR BackgroundWork : 5;
	UCHAR CPUIDBrand : 4;
	UCHAR Reserved3 : 4;
	UCHAR RdtscScaling : 3;
	UCHAR Reserved4 : 2;
	UCHAR UnalignedAtomicApproach : 2;
	UCHAR RunOnSingleCore : 1;
	UCHAR X64CPUID : 1;
	UCHAR PatchUnaligned : 1;
	UCHAR InterpreterOrJitter : 1;
	UCHAR Reserved5 : 1;
	UCHAR Reserved6 : 1;
	union
	{
		ULONGLONG Group1AsUINT64;
		struct _SDB_CSTRUCT_COBALT_PROCFLAG* Specified;
	};
} SDB_CSTRUCT_COBALT_PROCFLAG, * PSDB_CSTRUCT_COBALT_PROCFLAG;

typedef struct _SDB_CSTRUCT_COBALT_MODFLAG {
	ULONGLONG BarriersOverride;
	ULONG InternalSelfMod;
	ULONG PreciseExceptions;
	USHORT Reserved1;
	UCHAR Reserved2;
	UCHAR Barriers : 4;
	UCHAR Reserved3 : 4;
	UCHAR Reserved4 : 2;
	UCHAR CPUIDExtLeaf6 : 1;
	UCHAR JitCache : 1;
	UCHAR AlwaysLock : 1;
	UCHAR MergePushImmedPop : 1;
	UCHAR SseAlignmentChecks : 1;
	UCHAR StrongFloat : 1;
	UCHAR CHPE : 1;
	UCHAR VolatileMetadata : 1;
	UCHAR Reserved5 : 1;
	UCHAR Reserved6 : 1;
	union
	{
		ULONGLONG Group1AsUINT64;
		struct _SDB_CSTRUCT_COBALT_MODFLAG* Specified;
	};
} SDB_CSTRUCT_COBALT_MODFLAG, * PSDB_CSTRUCT_COBALT_MODFLAG;

typedef struct __declspec(align(2)) _SDB_ENTRY_MERGE_INFO
{
	USHORT EntryTag;
	USHORT MergeIdentifierTag;
	USHORT DefinitionAncestors[2];
	UCHAR IsMergeSupported : 1;
} SDB_ENTRY_MERGE_INFO, * PSDB_ENTRY_MERGE_INFO;

typedef struct _SDB_FILE_INFO
{
	DWORD dwSizeCb;
	PWSTR pwszFilePath;
	DWORD dwFileValidationFlags;
	DB_HEADER dbHeader;
	PWSTR pwszDescription;
	GUID guidDB;
} SDB_FILE_INFO, PSDB_FILE_INFO;

typedef struct _SDBMERGE_DB_INFO
{
	PWSTR FilePath;
	FILETIME FileTime;
	FILETIME SdbTime;
	GUID DatabaseId;
	GUID TargetDatabaseId;
	ULONG CrcChecksum;
	PWSTR CompilerVersion;
	ULONG RuntimePlatform;
	BOOL IsPreviousMerge;
} SDBMERGE_DB_INFO, * PSDBMERGE_DB_INFO;

#define APPCOMPAT_EXE_DATA_MAGIC 0xAC0DEDAB
//SWITCHCONTEXT_BRANCH_GUID_MAXCOUNT
#define BRANCHELEMENT_MAXCOUNT 48

#define SDB_MAX_EXES 16
#define SDB_MAX_LAYERS 8
#define SDB_MAX_SDBS 16

typedef struct tagSDBQUERYRESULT {
	TAGREF atrExes[SDB_MAX_EXES];	 //0x00
	DWORD  dwExeFlags[SDB_MAX_EXES]; //0x40
	TAGREF atrLayers[SDB_MAX_LAYERS];//0x80
	DWORD  dwLayerFlags;			 //0xA0
	TAGREF trApphelp;				 //0xA4
	DWORD  dwExeTagsCount;			 //0xA8
	DWORD  dwLayerTagsCount;		 //0xAC
	GUID   guidID;					 //0xB0
	DWORD  dwFlags;					 //0xC0
	DWORD  dwCustomSDBMap;			 //0xC4
	GUID   rgGuidDB[SDB_MAX_SDBS];	 //0xC8
} SDBQUERYRESULT, * PSDBQUERYRESULT; //0x1C8

typedef struct tagSDBENTRYINFO
{
	GUID guidID;
	DWORD dwFlags;
	ULONG tiData;
	GUID guidDB;
} SDBENTRYINFO, * PSDBENTRYINFO;

typedef struct tagSDBDATABASEINFO
{
	DWORD dwFlags;
	DWORD dwVersionMajor;
	DWORD dwVersionMinor;
	PWSTR pszDescription;
	GUID guidDB;
	DWORD dwRuntimePlatform;
} SDBDATABASEINFO, * PSDBDATABASEINFO;

typedef struct tagSDBMSIFINDINFO
{
	ULONG trMatch;
	GUID guidID;
	FIND_INFO sdbFindInfo;
	SDBMSILOOKUPSTATE sdbLookupState;
	DWORD dwCustomIndex;
} SDBMSIFINDINFO, * PSDBMSIFINDINFO;

typedef struct tagSDBMSITRANSFORMINFO
{
	LPCWSTR lpszTransformName;
	ULONG trTransform;
	ULONG trFile;
} SDBMSITRANSFORMINFO, * PSDBMSITRANSFORMINFO;

typedef struct _SDB_TAG_REF_MERGE_INFO
{
	USHORT DefinitionTag;
	USHORT ReferenceTag;
	USHORT ReferenceTagidTag;
	USHORT DefinitionLookupTag;
	USHORT ReferenceLookupTag;
	USHORT DefinitionAncestors[2];
	UCHAR IsMergeRefOnlyLookupSupported : 1;
} SDB_TAG_REF_MERGE_INFO, * PSDB_TAG_REF_MERGE_INFO;

typedef struct _SDB_REDIST_FIND_INFO
{
	SDBMSILOOKUPSTATE sdbLookupState;
	ULONG trRedistPackage;
	GUID guidRedistId;
} SDB_REDIST_FIND_INFO, * PSDB_REDIST_FIND_INFO;

typedef struct _SDB_REDIST_FILE_INFO
{
	LPCWSTR FileName;
	ULONGLONG MinVersion;
	ULONGLONG MaxVersion;
} SDB_REDIST_FILE_INFO, * PSDB_REDIST_FILE_INFO;

typedef struct tagSDBDEVICEINFO
{
	PWSTR szVendorId;
	PWSTR szDeviceId;
	PWSTR szSubVendorId;
	PWSTR szSubSystemId;
	ULONG dwModel;
	ULONG dwFamily;
	ULONG dwDate;
	ULONG dwRevision;
	ULONG dwCreatorRevision;
} SDBDEVICEINFO, * PSDBDEVICEINFO;

typedef struct tagSDBBMACHINEINFO
{
	PSDBDEVICEINFO AcpiInfo;
	PSDBDEVICEINFO OemInfo;
	PSDBDEVICEINFO BiosInfo;
	PSDBDEVICEINFO CpuInfo;
} SDBBMACHINEINFO, * PSDBBMACHINEINFO;

typedef struct tagSWITCH_CONTEXT_PLATFORM_DETAILS
{
	SWITCH_CONTEXT_PLATFORM_ID Id;
	GUID Guid;
	USHORT Major;
	USHORT Minor;
	LPCWSTR Name;
} SWITCH_CONTEXT_PLATFORM_DETAILS, * PSWITCH_CONTEXT_PLATFORM_DETAILS;

typedef struct tagSWITCH_CONTEXT_CREATE_PARAM
{
	ULONGLONG OsMaxVersionTested;
	ULONG TargetPlatform;
	PVOID ShimData;
	USHORT SubSystemMajorVersion;
	USHORT SubSystemMinorVersion;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	PVOID SupportedOsInfo;
} SWITCH_CONTEXT_CREATE_PARAM, * PSWITCH_CONTEXT_CREATE_PARAM;

typedef struct tagSWITCH_CONTEXT_ATTRIBUTE
{
	ULONGLONG ulContextUpdateCounter;	//+0x7e0 SwitchContextReferenceCount//SwitchBackContextReferenceNumber -- SbUpdateSwitchContextBasedOnDll ? SbSupportedOsList
	BOOL fAllowContextUpdate;			//+0x7e8 BOOL? PlatformIdMatch Checked?
	BOOL fEnableTrace;					//+0x7ec BOOL?
	HANDLE EtwHandle;					//+0x7f0 EtwEvent
} SWITCH_CONTEXT_ATTRIBUTE, * PSWITCH_CONTEXT_ATTRIBUTE;

typedef struct tagSWITCH_CONTEXT_DATA
{
	ULONGLONG ullOsMaxVersionTested;		//+0x7f8 SupportOS->MaxVersionTested/SupportOSVersionTest/ProcessOsMaxVersionTested[SbGetProcessOsMaxVersionTested]
	ULONG ulTargetPlatform;					//+0x800 DeviceFamily?

	ULONGLONG ullContextMinimum;			//+0x808 IsPackageImage-> 6.2.0.0 uncorrect: PACKAGE_VERSION	MinPackageVersion;	
	GUID guPlatform;						//+0x810 for PlatformId 48 [trExesGenericPlatformGuid] ?
	GUID guMinPlatform;						//+0x820 0x820 - 0x7e0 = 0x40 = 64 [trLayersGenericPlatformGuid]
	ULONG ulContextSource;					//+0x830 d.. with SubSystemVersion[1]/MaxversionTested/OperatingSystemVersion/4?/SdbContextQuery +64 ?dwOSVersionCheckFormType?
	ULONG ulElementCount;					//+0x834 BranchGuidTotalCount?
	GUID guElements[BRANCHELEMENT_MAXCOUNT];//+0x838
} SWITCH_CONTEXT_DATA, * PSWITCH_CONTEXT_DATA;//0x340 should be SwitchBranch

typedef struct tagSWITCH_CONTEXT
{
	SWITCH_CONTEXT_ATTRIBUTE Attribute;
	SWITCH_CONTEXT_DATA Data;
} SWITCH_CONTEXT, * PSWITCH_CONTEXT;

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
// 

//AppCompatData Fix fix
typedef struct _APPCOMPAT_EXE_DATA {
	WCHAR          szShimEngine[MAX_PATH];		//+0x0 C:\Windows\System32\apphelp.dll
	ULONG          cbSize;						//+0x208
	ULONG          dwMagic;						//+0x20c 
	BOOL           bLoadShimEngine;				//+0x210 dwFlags
	USHORT         uExeType;					//+0x214 dwMachine
	SDBQUERYRESULT SdbQueryResult;				//+0x218

	union
	{
		ULONG_PTR DbgLogChannels[128];
		struct
		{
			ASL_LOG_ENTRY AslLogEntry[11];		//+0x3e0  as it was on win 8 SepApplyDebugPolicy struct _ASL_LOG *g_ShimDebugLog/AslLogCreate/AslLogPublishToPeb
			ULONG AslReserved1;					//+0x7d4
			ULONGLONG AslReserved2;				//+0x7d8
		};//private
	};

	SWITCH_CONTEXT SwitchContext;				//+0x7e0
	DWORD dwParentProcessId;					//+0xb38
	WCHAR szParentImageName[MAX_PATH];			//+0xb3c
	WCHAR szParentCompatLayers[0x100];			//+0xd44 __COMPAT_LAYER 	WCHAR CompatLayerEnvValue[0x200] ???
	WCHAR szActiveCompatLayers[0x100];			//+0xf44 not  __COMMAND_LINE_OVERRIDE__ // __PROCESS_HISTORY
	ULONG uImageFileSize;						//+0x1144 
	ULONG uImageCheckSum;						//+0x1148
	BOOL bLatestOs;								//+0x114c AppCompatSupportOSMatchExpect
	BOOL bPackageId;							//+0x1150 ImageIsPackage
	BOOL bSwitchBackManifest;					//+0x1154 SxsSupportedOSVersionSpecified
	BOOL bUacManifest;							//+0x1158 RunLevelSpecified
	BOOL bLegacyInstaller;						//+0x115c OtherCompatModeEnabled
	ACTCTX_REQUESTED_RUN_LEVEL dwRunLevel;		//+0x1160 ACTCTX_REQUESTED_RUN_LEVEL
	
	DWORDLONG qwWinRTFlags;						//+0x1168 ULARGE_INTEGER ManagerFinalAppCompatFlag;
	PVOID pHookCOM;								//+0x1170 ntdll!SE_COM_AddServer HookComInterface
	HANDLE pComponentOnDemandEtwEvent;			//+0x1178 ntdll!LdrpCheckComponentOnDemandEtwEvent, related to QuirkComponent CodeId?
	PVOID pQuirks;								//+0x1180 指向一个结构 ApphelpCacheServiceMapQuirks//QuirkManager QuirksTable
	ULONG ulQuirksSize;							//+0x1188

	SDB_CSTRUCT_COBALT_PROCFLAG CobaltProcFlags;//+0x1190
	ULONG FullMatchDbSizeCb;					//+0x11b8 PdbBufferLength
	ULONG FullMatchDbOffset;					//+0x11bc PdbBufferOffset					
} APPCOMPAT_EXE_DATA, * PAPPCOMPAT_EXE_DATA;	//+0x11c0 == 4544
// PdbBuffer next to  _APPCOMPAT_EXE_DATA

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

typedef enum _RUNLEVEL
{
	RUNLEVEL_LUA = 0x0,			// 应用程序应使用与父进程相同的 Windows 权限和用户权限运行。此设置相当于没有应用程序的应用程序兼容性数据库。应用程序以与启动它的父进程相同的权限启动，这减少了应用程序的安全风险。这是因为对于大多数应用程序来说，父级是 Explorer.exe，它作为标准用户应用程序运行。从以完全管理员身份运行的 cmd.exe shell 启动的 RunAsInvoker 应用程序将使用完全管理员访问令牌“以调用者身份运行”。
	RUNLEVEL_HIGHEST = 0x1,		// 该应用程序可由管理员和标准用户运行，并根据用户的特权和用户权限调整其行为;该应用程序需要比标准用户更高的特权和用户权限，但不要求用户是本地管理员组的成员。
	RUNLEVEL_ADMIN = 0x2,		// 应用程序应仅为管理员运行，必须使用完整的管理员访问令牌启动，并且无法在标准用户上下文中正确运行。此请求的执行级别标记是为要求用户是本地管理员组成员的 Windows Vista 之前的应用程序保留的。	
	RUNLEVEL_MAX_NON_UIA = 0x3,
	RUNLEVEL_LUA_UIA = 0x10,
	RUNLEVEL_HIGHEST_UIA = 0x11,
	RUNLEVEL_ADMIN_UIA = 0x12,
	RUNLEVEL_MAX = 0x13,
}RUNLEVEL;

//FIX_FLAG
typedef struct _APPCOAMPAT_FLAG_LUA
{
	RUNLEVEL RunLevel;
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

//
// ntdll!SbSelectProcedure(ULONG signature, ULONG unk, const SWITCHBRANCH_SCENARIO_TABLE* pScenarioTable, ULONG scenarioIndex);
// 
//=========================================================================================
// https://undoc.airesoft.co.uk/ntdll.dll/SbSelectProcedure.php
// branch details in a table entry should be ordered from the highest windows compatability manifest version 
// that makes sense to the lowest. So the win10 branch first, then win8.1, then win8, etc
//
// You can skip any you'd like e.g. only have entries for Win10 then Win7 without any others 

typedef PVOID(NTAPI* pfnBranchFunc)(PVOID);

typedef struct _SWITCHBRANCH_BRANCH_DETAILS
{
	PCSTR pSpecificName; // the name of this branch
	pfnBranchFunc pBranch;
	ULONG unk; // always 1
	// 4-byte paadding on x64
	PCSTR pDescription;
	ULONG unk2; // 
	ULONG unk3; // always 0
	ULONG unk4; // always 1
	ULONG unk5; // always 0
	// the windows compatability guid specified in the manifest
	// that results in this branch being taken
	GUID windowsCompatGuid;
	// an id for this branch
	GUID branchGuid;
} SWITCHBRANCH_BRANCH_DETAILS, * PSWITCHBRANCH_BRANCH_DETAILS;

typedef struct _SWITCHBRANCH_SCENARIO_TABLE_ENTRY
{
	PCSTR pBranchName;
	PCSTR pBranchDescription;
	PCSTR pBranchReason;
	ULONG unk;  // always 1
	ULONG unk2; // always 0
	ULONG unk3; // always 0
	ULONG unk4; // always 1
	ULONG unk5; // always 0
	GUID scenarioGuid;
	ULONG numScenarioBranches;
	SWITCHBRANCH_BRANCH_DETAILS branches[ANYSIZE_ARRAY]; // numScenarioBranches long
} SWITCHBRANCH_SCENARIO_TABLE_ENTRY, * PSWITCHBRANCH_SCENARIO_TABLE_ENTRY;

typedef struct _SWITCHBRANCH_SCENARIO_TABLE_ENTRIES
{
	ULONG numScenarios;
	SWITCHBRANCH_SCENARIO_TABLE_ENTRY* pEntries[ANYSIZE_ARRAY]; // numScenarios long
} SWITCHBRANCH_SCENARIO_TABLE_ENTRIES, * PSWITCHBRANCH_SCENARIO_TABLE_ENTRIES;

typedef struct _SWITCHBRANCH_CACHED_MODULE_TABLE
{
	ULONG64 changeCount;
	ULONG unk;
	ULONG numScenarios;
	PVOID pScenarios[ANYSIZE_ARRAY]; // numScenarios in size
} SWITCHBRANCH_CACHED_MODULE_TABLE, * PSWITCHBRANCH_CACHED_MODULE_TABLE;

typedef PVOID(WINAPI* pfnFilterFunc)(PVOID);

typedef struct _SWITCHBRANCH_SCENARIO_TABLE
{
	ULONG tag; // always 'EsLk', not ever checked even on checked builds
	ULONG unk; // Always 0x1000000
	SWITCHBRANCH_CACHED_MODULE_TABLE* pModuleTable;
	PVOID unk2; // always 0
	SWITCHBRANCH_SCENARIO_TABLE_ENTRIES* pScenarios;
	// this function probably has greater significance, but all occurances just return a string like
	// SbFilterProcedure_DdrawNamespace,
	// SbFilterProcedure_Scenario etc
	pfnFilterFunc filterProcedure;
} SWITCHBRANCH_SCENARIO_TABLE, * PSWITCHBRANCH_SCENARIO_TABLE;
//=========================================================================================

#endif // !_APPHELP_HEADER