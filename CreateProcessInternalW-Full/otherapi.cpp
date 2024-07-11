#include "ntapi.hpp"
#include "otherapi.hpp"
#include "csrss.hpp"
#include "syscalls.hpp"
#include <SoftPub.h>

#pragma comment(lib,"WinTrust")
#pragma warning(disable: 4996)
#pragma warning(disable: 5056) 
static UNICODE_STRING RestrictedName = RTL_CONSTANT_STRING(L"Restricted");
static UNICODE_STRING LocalName = RTL_CONSTANT_STRING(L"Local");
static UNICODE_STRING GlobalName = RTL_CONSTANT_STRING(L"Global");
static UNICODE_STRING SessionName = RTL_CONSTANT_STRING(L"Session");
static UNICODE_STRING AppContainerNamedObjectsName = RTL_CONSTANT_STRING(L"AppContainerNamedObjects");


// 2147483647
#ifndef NTSTRSAFE_MAX_CCH
#define NTSTRSAFE_MAX_CCH 0x7FFFFFFF 
#endif

#ifndef NTSTRSAFE_PWSTR
typedef _Null_terminated_ wchar_t* NTSTRSAFE_PWSTR;
typedef CONST NTSTRSAFE_PWSTR NTSTRSAFE_PCWSTR;
#endif

#ifndef NTSTRSAFEAPI
#define NTSTRSAFEAPI	static __inline NTSTATUS NTAPI
#endif

#ifndef _NTSTRSAFE_H_INCLUDED_

//
// Out_writes_(cchDest) _Always_(_Post_z_) NTSTRSAFE_PWSTR pszDest,
// _In_ size_t cchDest,
// _In_ _Printf_format_string_ NTSTRSAFE_PWSTR pszFormat,
//


NTSTRSAFEAPI RtlStringCchPrintfW(wchar_t* pszDest, size_t cchDest, const wchar_t* pszFormat, ...)
{
	NTSTATUS Status = 0;
	va_list argList;
	va_start(argList, pszFormat);
	if (cchDest > NTSTRSAFE_MAX_CCH)
	{
		if (cchDest > 0)
			*pszDest = L'\0';
		return STATUS_INVALID_PARAMETER;
	}
	
	//Status = RtlStringVPrintfWorkerW(pszDest, cchDest, pszFormat, argList);
	size_t cchMax = cchDest - 1;
	int iRet = _vsnwprintf(pszDest, cchMax, pszFormat, argList);

	if ((iRet < 0) || (((size_t)iRet) > cchMax))
	{
		*pszDest = L'\0';
		Status = STATUS_BUFFER_OVERFLOW;
	}
	else if (((size_t)iRet) == cchMax)
	{
		pszDest += cchMax;
		*pszDest = L'\0';
	}

	va_end(argList);

	return Status;
}
#endif


#define tempargcount (24 - 11)
NTSTATUS  BasepConvertWin32AttributeList(
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
	PWIN32K_SYSCALL_FILTER Win32kFilter,//11
	...
)
{
	// I know this is unsafe...
	// Not tested yet!
	va_list vargument;
	va_start(vargument, Win32kFilter);
	int i = 0;

	PVOID VArgument[tempargcount] = { 0 }; //13
	RtlSecureZeroMemory(VArgument, sizeof(VArgument));
	BOOL FsctlMitigationSupported = FALSE;
	// 找不到特征码的无奈
	// 对于 Windows 11 21H2 来说
	if (OSBuildNumber < 25295 && NtdllRevision)
	{
		if (NtdllBuildNumber < 19090 && NtdllRevision >= 3636)		// [10.0.19041.3636]
		{
			FsctlMitigationSupported = TRUE;
		}
		else if (NtdllBuildNumber <= 22000 && NtdllRevision >= 2600)// [10.0.22000.2538] 当且仅当2023/11 开始出现 [10.0.22000.2600] 
		{
			FsctlMitigationSupported = TRUE;
		}
		else if (NtdllBuildNumber <= 22631 && NtdllRevision > 2134)	// [10.0.22621.2134]
		{
			FsctlMitigationSupported = TRUE;
		}
	}
	else
	{
		FsctlMitigationSupported = TRUE;
	}

	PVOID TempArgument = va_arg(vargument, PVOID);
	if (FsctlMitigationSupported)
	{
		VArgument[i++] = TempArgument;//FsctlMitigationSupported 还没想到一个完美的方案
		wprintf(L"[!] FsctlMitigation Supported!\n");
	}

	TempArgument = va_arg(vargument, PVOID);
	if (OSBuildNumber >= 19090 || (NtdllRevision && NtdllRevision >= 1202))
	{
		VArgument[i++] = TempArgument;//ComponentFilter
	}
	//wprintf(L"[!] NtdllRevision: %hd\n", NtdllRevision);

	for (int j = 0; j < 6; j++)
	{
		VArgument[i++] = va_arg(vargument, PVOID);
	}

	TempArgument = va_arg(vargument, PVOID);
	if (OSBuildNumber > 22000)// > 22000
	{
		VArgument[i++] = TempArgument;//TrustletAttributes
	}

	TempArgument = va_arg(vargument, PVOID);
	if (OSBuildNumber >= 21313)
	{
		VArgument[i++] = TempArgument;//ProcessFlags
	}

	VArgument[i++] = va_arg(vargument, PVOID);
	VArgument[i++] = va_arg(vargument, PVOID);
	VArgument[i++] = va_arg(vargument, PVOID);//extra, optional

	va_end(vargument);
	return BasepConvertWin32AttributeList_inline(
		lpAttributeList,
		ConvertType,
		ExtendedFlags,
		PackageFullName,
		SecurityCapabilities,
		HasHandleList,
		ParentProcessHandle,		// PSEUDOCONSOLE_INHERIT_CURSOR ?
		ConsoleHandleInfo,			// CONSOLE_HANDLE_INFO   //IN ProcessParameters ?<- CONSOLE_IGNORE_CTRL_C = 0x1// ? = 0x2// ? = 0x4 ???
		MitigationOptions,			// PS_MITIGATION_OPTIONS_MAP 
		MitigationAuditOptions,		// PS_MITIGATION_AUDIT_OPTIONS_MAP
		Win32kFilter,				// WIN32K_SYSCALL_FILTER //12
		VArgument[0],
		VArgument[1],				// int // ULONG ComponentFilter
		VArgument[2],				// MAXVERSIONTESTED_INFO ???
		VArgument[3],				// PS_BNO_ISOLATION_PARAMETERS
		VArgument[4],				// DWORD (PROCESS_CREATION_DESKTOP_APP_*)
		VArgument[5],				// in ISOLATION_MANIFEST_PROPERTIES* // rev (diversenok) // since 19H2+
		VArgument[6],
		VArgument[7],
		VArgument[8],
		VArgument[9],
		VArgument[10],
		VArgument[11],
		VArgument[12]);				// ProcThreadAttributeMax OPTIONAL
}

BOOLEAN BasepFreeBnoIsolationParameter(PPS_BNO_ISOLATION_PARAMETERS BnoIsolationParameter)
{
	BOOLEAN bStatus = FALSE;
    if (BnoIsolationParameter)
    {
        if (BnoIsolationParameter->Handles)
        {
            for (DWORD i = 0; i < BnoIsolationParameter->HandleCount; i++)
            {
                if (BnoIsolationParameter->Handles[i])
                    NtClose(BnoIsolationParameter->Handles[i]);
            }
            bStatus = RtlFreeHeap(RtlProcessHeap(), 0, BnoIsolationParameter->Handles);
            BnoIsolationParameter->Handles = NULL;
            BnoIsolationParameter->HandleCount = 0;
        }
    }
    return bStatus;
}


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
)
{	
	NTSTATUS Status = 0;
	BOOLEAN IsDllPathHeapAllocated = FALSE;
	PRTL_USER_PROCESS_PARAMETERS CurrentProcessParameters = NULL;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RTL_USER_PROCESS_PARAMETERS TemplateProcessParameters = { 0 };

	TemplateProcessParameters.ImagePathName = *ImageName;
	TemplateProcessParameters.Environment = Environment;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.CommandLine, CommandLine);
	if (!NT_SUCCESS(Status))
		goto Fail;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.CurrentDirectory.DosPath, CurrentDirectory);
	if (!NT_SUCCESS(Status))
		goto Fail;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.RedirectionDllName, AppXRedirectionDllName);
	if (!NT_SUCCESS(Status))
		goto Fail;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.DllPath, AppXDllDirectory);
	if (!NT_SUCCESS(Status))
		goto Fail;

	if (!AppXDllDirectory && !IsPackageProcess && (ProcessFlags & PROCESS_CREATE_FLAGS_PACKAGE_BREAKAWAY) == 0)// NoDllPath
	{
		Status = LdrGetDllDirectory(&TemplateProcessParameters.DllPath);

		if (TemplateProcessParameters.DllPath.Length > sizeof(UNICODE_NULL) && Status == STATUS_BUFFER_TOO_SMALL)
		{
			
			TemplateProcessParameters.DllPath.Buffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, TemplateProcessParameters.DllPath.Length);

			if (!TemplateProcessParameters.DllPath.Buffer)
			{
				Status = STATUS_NO_MEMORY;
				goto Fail;
			}

			TemplateProcessParameters.DllPath.MaximumLength = TemplateProcessParameters.DllPath.Length;
			IsDllPathHeapAllocated = TRUE;

			Status = LdrGetDllDirectory(&TemplateProcessParameters.DllPath);
			if (!NT_SUCCESS(Status))
				goto Fail;

		}
		else
		{
			RtlInitUnicodeString(&TemplateProcessParameters.DllPath, NULL);
			IsDllPathHeapAllocated = FALSE;
		}
	}

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.DesktopInfo, StartInfo->lpDesktop);
	if (!NT_SUCCESS(Status))
		goto Fail;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.ShellInfo, StartInfo->lpReserved);
	if (!NT_SUCCESS(Status))
		goto Fail;

	TemplateProcessParameters.RuntimeData.Buffer = (PWSTR)StartInfo->lpReserved2;
	TemplateProcessParameters.RuntimeData.Length = StartInfo->cbReserved2;
	TemplateProcessParameters.RuntimeData.MaximumLength = TemplateProcessParameters.RuntimeData.Length;

	if (!StartInfo->lpTitle)
		StartInfo->lpTitle = (LPWSTR)lpApplicationName;

	Status = RtlInitUnicodeStringEx(&TemplateProcessParameters.WindowTitle, StartInfo->lpTitle);
	if (!NT_SUCCESS(Status))
		goto Fail;
	Status = RtlCreateProcessParametersWithTemplate(&ProcessParameters, &TemplateProcessParameters, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	if (!NT_SUCCESS(Status))
		goto Fail;

	ProcessParameters->StartingX = StartInfo->dwX;
	ProcessParameters->StartingY = StartInfo->dwY;
	ProcessParameters->CountX = StartInfo->dwXSize;
	ProcessParameters->CountY = StartInfo->dwYSize;
	ProcessParameters->CountCharsX = StartInfo->dwXCountChars;
	ProcessParameters->CountCharsY = StartInfo->dwYCountChars;
	ProcessParameters->FillAttribute = StartInfo->dwFillAttribute;
	ProcessParameters->WindowFlags = StartInfo->dwFlags;
	ProcessParameters->ShowWindowFlags = StartInfo->wShowWindow;

	if (dwCreationFlags & CREATE_NEW_PROCESS_GROUP)
		ProcessParameters->ProcessGroupId = 0;
	else
		ProcessParameters->ProcessGroupId = NtCurrentPeb()->ProcessParameters->ProcessGroupId;

	if (StartInfo->dwFlags & (STARTF_USESTDHANDLES | STARTF_USEHOTKEY | STARTF_HASSHELLDATA))
	{
		if (ParentProcessHandle || (StartInfo->dwFlags & STARTF_USESTDHANDLES) == 0 || (ProcessFlags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES))
		{
			ProcessParameters->StandardInput = StartInfo->hStdInput;
			ProcessParameters->StandardOutput = StartInfo->hStdOutput;
			ProcessParameters->StandardError = StartInfo->hStdError;
		}
		else
		{
			ProcessParameters->StandardInput = NULL;
			ProcessParameters->StandardOutput = NULL;
			ProcessParameters->StandardError = NULL;
		}
	}

	if (dwCreationFlags & DETACHED_PROCESS)
	{
		ProcessParameters->ConsoleHandle = CONSOLE_DETACHED_PROCESS;
	}
	else if (dwCreationFlags & CREATE_NEW_CONSOLE)
	{
		ProcessParameters->ConsoleHandle = CONSOLE_NEW_CONSOLE; 
	}
	else if (dwCreationFlags & CREATE_NO_WINDOW)
	{
		ProcessParameters->ConsoleHandle = CONSOLE_CREATE_NO_WINDOW;
	}
	else
	{
		if (ConsoleReference && ConsoleReference->ConsoleRererenceHandle)
		{
			ProcessParameters->ConsoleHandle = *ConsoleReference->ConsoleRererenceHandle;
			ProcessParameters->ConsoleFlags |= CONSOLE_HANDLE_REFERENCE;
			if (ConsoleReference->ConsoleRererenceType)// PseudoConsole
				ProcessParameters->ConsoleFlags |= CONSOLE_USING_PTY_REFERENCE;
		}
		else
		{
			ProcessParameters->ConsoleHandle = ConhostConsoleHandle;
			if (!ProcessParameters->ConsoleHandle)
				ProcessParameters->ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
		}
		if ((StartInfo->dwFlags & (STARTF_USESTDHANDLES | STARTF_USEHOTKEY | STARTF_HASSHELLDATA)) == 0 && DefaultInheritOnly)
		{
			CurrentProcessParameters = NtCurrentPeb()->ProcessParameters;
			if ((CurrentProcessParameters->WindowFlags & STARTF_USEHOTKEY) == 0)
			{
				ProcessParameters->StandardInput = CurrentProcessParameters->StandardInput;
				CurrentProcessParameters = NtCurrentPeb()->ProcessParameters;
			}
			if ((CurrentProcessParameters->WindowFlags & STARTF_HASSHELLDATA) == 0)
			{
				ProcessParameters->StandardOutput = CurrentProcessParameters->StandardOutput;
				CurrentProcessParameters = NtCurrentPeb()->ProcessParameters;
			}
			ProcessParameters->StandardError = CurrentProcessParameters->StandardError;
		}

	}

	if ((dwCreationFlags & CREATE_NEW_PROCESS_GROUP) != 0 && (dwCreationFlags & CREATE_NEW_CONSOLE) == 0) 
		ProcessParameters->ConsoleFlags |= CONSOLE_IGNORE_CTRL_C;

	ProcessParameters->Flags |= NtCurrentPeb()->ProcessParameters->Flags & RTL_USER_PROC_DISABLE_HEAP_DECOMMIT;

	if (IsDllPathHeapAllocated)
		RtlFreeHeap(RtlProcessHeap(), 0, TemplateProcessParameters.DllPath.Buffer);

	return ProcessParameters;

Fail:
	if (ProcessParameters)
		RtlDestroyProcessParameters(ProcessParameters);

	BaseSetLastNTError(Status);
	return NULL;
}

BOOL BasepAdjustApplicationPath(IN OUT PUNICODE_STRING ApplicationPath)
{
	DWORD CharLength = 0;

	CharLength = ApplicationPath->Length / sizeof(WCHAR);
	if (!CharLength)
		return TRUE;
	
	// Check 1
	for (DWORD i = 0; i < CharLength; i++)
	{
		if (ApplicationPath->Buffer[i] == '/')
			return FALSE;// Adjust Required
	}
	
	// Check 2 
	for (DWORD j = 0; j < CharLength; j++)
	{
		if (ApplicationPath->Buffer[j] == '\\' && ApplicationPath->Buffer[(j + 1)] == '\\')
			return FALSE;// Adjust Required
	}

	// Check 3, Simple Adjusting
	do
	{
		if (ApplicationPath->Buffer[--CharLength] == ' ')
			ApplicationPath->Length -= sizeof(WCHAR);

		else
			break;

	} while (CharLength != 0);

	return TRUE;
}

NTSTATUS BasepGetNamedObjectDirectoryForToken(
	IN  HANDLE TokenHandle,
	IN  BOOL IsRemoteCrossSession,
	IN  BOOL CheckTokenBnoIsolation,
	IN  ACCESS_MASK DesiredAccessReserved,
	OUT PHANDLE DirectoryHandle)
{

	PTOKEN_APPCONTAINER_INFORMATION pAppContainerTokenInfo = NULL;
	NTSTATUS Status = 0;
	LONG Length = 0;
	ULONG AppContainerSidLength = 0;
	ULONG ReturnLength = 0;
	HANDLE TempDirectoryHandle = NULL;
	UNICODE_STRING szName = { 0 };
	ULONG SessionId = 0;
	HANDLE DirectoryObjectHandle = NULL;
	HANDLE RootDirectory = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ULONG ulIsAppContainer = 0;
	ULONG ulIsPrivateNamespace = 0;
	APPCONTAINER_SID_TYPE TokenSidType = NotAppContainerSidType;
	PSID AppContainerParentSid = 0;
	UNICODE_STRING AppContainerTokenSidString = { 0 };
	UNICODE_STRING SidString = { 0 };
	UNICODE_STRING ChildAppContainerObjectName;
	UCHAR bTokenUser[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE] = { 0 };// [sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES]
	PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
	WCHAR szBaseNamedObjectDirectory[MAX_SESSION_PATH] = { 0 };
	TOKEN_BNO_ISOLATION_INFORMATION TokenBnoIsolationInfo = { 0 };
	WCHAR pszDest[MAX_PATH] = { 0 };

	memset(pszDest, 0, sizeof(pszDest));

	__try
	{
		Status = NtQueryInformationToken(TokenHandle, TokenSessionId, &SessionId, sizeof(ULONG), &ReturnLength);
		if (!NT_SUCCESS(Status))
			leave;

		Status = NtQueryInformationToken(TokenHandle, TokenIsAppContainer, &ulIsAppContainer, sizeof(ULONG), &ReturnLength);
		if (!NT_SUCCESS(Status))
			leave;

		Status = NtQueryInformationToken(TokenHandle, TokenPrivateNameSpace, &ulIsPrivateNamespace, sizeof(ULONG), &ReturnLength);
		if (!NT_SUCCESS(Status))
			leave;
		
		if (ulIsPrivateNamespace)
		{
			Status = NtQueryInformationToken(TokenHandle, TokenUser, pTokenUser, SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER), &ReturnLength);
			if (!NT_SUCCESS(Status))
				leave;

			Status = RtlConvertSidToUnicodeString(&SidString, pTokenUser->User.Sid, TRUE);
			if (!NT_SUCCESS(Status))
				leave;
		}

		if (ulIsAppContainer)
		{
			// AppContainer, [SECURITY_CHILD_PACKAGE_RID_COUNT] uncorrected?
			AppContainerSidLength = RtlLengthRequiredSid(SECURITY_CHILD_PACKAGE_RID_COUNT) + sizeof(TOKEN_APPCONTAINER_INFORMATION);
			pAppContainerTokenInfo = (PTOKEN_APPCONTAINER_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), 0, AppContainerSidLength);
			if (!pAppContainerTokenInfo)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				leave;
			}

			Status = NtQueryInformationToken(TokenHandle, TokenAppContainerSid, pAppContainerTokenInfo, AppContainerSidLength, &ReturnLength);
			if (Status == STATUS_BUFFER_TOO_SMALL)
			{
				RtlFreeHeap(RtlProcessHeap(), 0, pAppContainerTokenInfo);
				pAppContainerTokenInfo = (PTOKEN_APPCONTAINER_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), 0, ReturnLength);

				if (pAppContainerTokenInfo)
				{
					Status = NtQueryInformationToken(TokenHandle, TokenAppContainerSid, pAppContainerTokenInfo, ReturnLength, &ReturnLength);
				}
				else
					Status = STATUS_INSUFFICIENT_RESOURCES;
			}

			if (!NT_SUCCESS(Status))
				leave;

			Status = RtlStringCchPrintfW(
				szBaseNamedObjectDirectory,// szAppContainerBaseNamedObjectDirectory
				MAX_PATH,
				L"%ws\\%ld\\AppContainerNamedObjects",
				L"\\Sessions",
				SessionId);
			if (!NT_SUCCESS(Status))
				leave;

			if (IsRemoteCrossSession)
			{
				RtlInitUnicodeString(&szName, szBaseNamedObjectDirectory);
			}
			else
			{
				szName = BaseStaticServerData->AppContainerNamedObjectsDirectory;
				if (szName.Buffer)// Delta
				{
					szName.Buffer = (PWSTR)((char*)szName.Buffer
						+ (ULONGLONG)BASE_SHARED_SERVER_DATA
						- (ULONGLONG)BASE_SHARED_SERVER_DATA->RemoteBaseAddress);
				}	
				else
				{
					szName.Buffer = NULL;
				}
			}

			InitializeObjectAttributes(&ObjectAttributes, &szName, OBJ_CASE_INSENSITIVE, NULL, NULL);
			Status = NtOpenDirectoryObject(&RootDirectory, DIRECTORY_TRAVERSE, &ObjectAttributes);
			if (!NT_SUCCESS(Status))
				leave;

			if (ulIsPrivateNamespace)
			{
				InitializeObjectAttributes(&ObjectAttributes, &SidString, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);
				Status = NtOpenDirectoryObject(&TempDirectoryHandle, DIRECTORY_TRAVERSE, &ObjectAttributes);
				if (!NT_SUCCESS(Status))
					leave;

				NtClose(RootDirectory);
				RootDirectory = TempDirectoryHandle;
				TempDirectoryHandle = NULL;
			}

			Status = RtlGetAppContainerSidType(pAppContainerTokenInfo->TokenAppContainer, &TokenSidType);
			if (!NT_SUCCESS(Status))
				leave;

			if (TokenSidType == ParentAppContainerSidType)
			{
				Status = RtlConvertSidToUnicodeString(&AppContainerTokenSidString, pAppContainerTokenInfo->TokenAppContainer, TRUE);
				if (!NT_SUCCESS(Status))
					leave;

				InitializeObjectAttributes(&ObjectAttributes, &AppContainerTokenSidString, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);
				Status = NtOpenDirectoryObject(&DirectoryObjectHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes);

			}
			else // Child AppContainer (1)
			{
				Status = RtlGetAppContainerParent(pAppContainerTokenInfo->TokenAppContainer, &AppContainerParentSid);
				if (!NT_SUCCESS(Status))
					leave;

				Status = RtlConvertSidToUnicodeString(&AppContainerTokenSidString, AppContainerParentSid, TRUE);
				if (!NT_SUCCESS(Status))
					leave;

				//SECURITY_CHILD_PACKAGE_RID_COUNT
				Status = RtlStringCchPrintfW(
					pszDest,
					MAX_PATH,
					L"%s\\%u-%u-%u-%u",
					AppContainerTokenSidString.Buffer,
					*RtlSubAuthoritySid(pAppContainerTokenInfo->TokenAppContainer, SECURITY_PARENT_PACKAGE_RID_COUNT + 0),
					*RtlSubAuthoritySid(pAppContainerTokenInfo->TokenAppContainer, SECURITY_PARENT_PACKAGE_RID_COUNT + 1),
					*RtlSubAuthoritySid(pAppContainerTokenInfo->TokenAppContainer, SECURITY_PARENT_PACKAGE_RID_COUNT + 2),
					*RtlSubAuthoritySid(pAppContainerTokenInfo->TokenAppContainer, SECURITY_PARENT_PACKAGE_RID_COUNT + 3)
				);

				if (!NT_SUCCESS(Status))
					leave;

				RtlInitUnicodeString(&ChildAppContainerObjectName, pszDest);
				InitializeObjectAttributes(&ObjectAttributes, &ChildAppContainerObjectName, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);
				Status = NtOpenDirectoryObject(&DirectoryObjectHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes);
			}
		}
		else
		{
			if (!ulIsPrivateNamespace && SessionId == RtlGetCurrentServiceSessionId())
			{
				Length = MAX_SESSION_PATH;
				int i = 0;
				
				//
				// ??? WTF
				//
				while (Length != MAX_PATH - sizeof(UNICODE_NULL) - NTSTRSAFE_MAX_CCH) 
				{
					wchar_t widechar = *(wchar_t*)((char*)L"\\BaseNamedObjects" + 2 * i);
					if (widechar == NULL)
						break;

					if (Length == 0)
					{
						Status = STATUS_BUFFER_OVERFLOW;
						break;
					}
						
					szBaseNamedObjectDirectory[i++] = widechar;
					Length--;
				}
				szBaseNamedObjectDirectory[i] = NULL;
			}
			else
			{
				Status = RtlStringCchPrintfW(szBaseNamedObjectDirectory, MAX_SESSION_PATH, L"%ws\\%ld\\BaseNamedObjects", L"\\Sessions", SessionId);
			}
			
			dprintf(L"[x] szBaseNamedObjectDirectory: %ls\n", szBaseNamedObjectDirectory);

			if (!NT_SUCCESS(Status))
				leave;

			if (ulIsPrivateNamespace)
			{
				if (IsRemoteCrossSession)
				{
					RtlInitUnicodeString(&szName, szBaseNamedObjectDirectory);
				}
				else
				{
					szName = BaseStaticServerData->PrivateNameObjectsDirectory;
					if (szName.Buffer)// Delta
					{
						szName.Buffer = (PWSTR)((char*)szName.Buffer
							+ (ULONGLONG)BASE_SHARED_SERVER_DATA
							- (ULONGLONG)BASE_SHARED_SERVER_DATA->RemoteBaseAddress);
					}
					else
					{
						szName.Buffer = NULL;
					}
				}

				InitializeObjectAttributes(&ObjectAttributes, &szName, OBJ_CASE_INSENSITIVE, NULL, NULL);
				Status = NtOpenDirectoryObject(&RootDirectory, DIRECTORY_TRAVERSE, &ObjectAttributes);

				if (!NT_SUCCESS(Status))
					leave;
			}
			else
			{
				if (IsRemoteCrossSession)
				{
					RtlInitUnicodeString(&szName, szBaseNamedObjectDirectory);
				}
				else
				{	
					szName = BaseStaticServerData->NamedObjectDirectory;					
					if (szName.Buffer)// Delta
					{
						szName.Buffer = (PWSTR)((char*)szName.Buffer
							+ (ULONGLONG)BASE_SHARED_SERVER_DATA
							- (ULONGLONG)BASE_SHARED_SERVER_DATA->RemoteBaseAddress);
					}
					else
					{
						szName.Buffer = NULL;
					}
				}
				RootDirectory = NULL;
			}
			dprintf(L"[x] 2 szName: %ls\n", szName.Buffer);
			InitializeObjectAttributes(&ObjectAttributes, &szName, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);
			Status = NtOpenDirectoryObject(&DirectoryObjectHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes);
			dprintf(L"[x] 2 NtOpenDirectoryObject Status: 0x%08lx\n", Status);
			// Suffer Restricted?
			if (!NT_SUCCESS(Status))
			{
				Status = NtOpenDirectoryObject(&TempDirectoryHandle, DIRECTORY_QUERY, &ObjectAttributes);
				if (!NT_SUCCESS(Status))
					leave;

				InitializeObjectAttributes(&ObjectAttributes, &RestrictedName, OBJ_CASE_INSENSITIVE, TempDirectoryHandle, NULL);
				Status = NtOpenDirectoryObject(&DirectoryObjectHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes);
				NtClose(TempDirectoryHandle);
				TempDirectoryHandle = NULL;
			}
		}

		if (!NT_SUCCESS(Status))
			leave;

		if (CheckTokenBnoIsolation)
		{
			Status = NtQueryInformationToken(TokenHandle, TokenBnoIsolation, &TokenBnoIsolationInfo, sizeof(TOKEN_BNO_ISOLATION_INFORMATION) + BNOISOLATION_PREFIX_MAXLENGTH, &ReturnLength);
			if (!NT_SUCCESS(Status))
				leave;

			if (!TokenBnoIsolationInfo.IsolationEnabled)
			{
				*DirectoryHandle = DirectoryObjectHandle;
				DirectoryObjectHandle = NULL;
				leave;
			}

			RtlInitUnicodeString(&szName, TokenBnoIsolationInfo.IsolationPrefix);

			InitializeObjectAttributes(&ObjectAttributes, &szName, OBJ_CASE_INSENSITIVE, DirectoryObjectHandle, NULL);
			Status = NtOpenDirectoryObject(&TempDirectoryHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes);
			if (!NT_SUCCESS(Status))
				leave;
	
			NtClose(DirectoryObjectHandle);
			DirectoryObjectHandle = TempDirectoryHandle;
			TempDirectoryHandle = NULL;
		}
	
		*DirectoryHandle = DirectoryObjectHandle;
		DirectoryObjectHandle = NULL;
		
	}
	__finally
	{
		if (AppContainerTokenSidString.Buffer)
			RtlFreeUnicodeString(&AppContainerTokenSidString);

		if (DirectoryObjectHandle)
			NtClose(DirectoryObjectHandle);

		if (RootDirectory)
			NtClose(RootDirectory);

		if (AppContainerParentSid)
			RtlFreeSid(AppContainerParentSid);

		if (pAppContainerTokenInfo)
			RtlFreeHeap(RtlProcessHeap(), 0, pAppContainerTokenInfo);

		if (SidString.Buffer)
			RtlFreeUnicodeString(&SidString);
	}
	dprintf(L"[x] xxx Status: 0x%08lx\n", Status);
	return Status;
}

static UNICODE_STRING GloablObjectDirectoryName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects");

NTSTATUS BasepCreateBnoIsolationSymbolicLinks(
	IN  HANDLE BaseNamedObjectDirectory,
	IN  HANDLE BnoRootDirectory,
	IN  PUNICODE_STRING IsolationPrefix,
	OUT HANDLE* lpLocalLink,
	OUT HANDLE* lpGlobalLink,
	OUT HANDLE* lpSessionLink,
	OUT HANDLE* lpAppContainerNamedObjectsLink
)
{
	dprintf(L"[1] Pre NtQueryObject Status: 0x%p\n", BasepCreateBnoIsolationSymbolicLinks);
	NTSTATUS Status;
	ULONG ObjectNameLength = 0;
	HANDLE LocalLinkHandle = NULL;
	HANDLE GlobalLinkHandle = NULL;
	HANDLE SessionLinkHandle = NULL;
	HANDLE AppContainerNamedObjectsLinkHandle = NULL;
	UNICODE_STRING LinkTargetName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PVOID ObjectNameHeapBuffer = NULL;
	WCHAR TargetNameBuffer[MAX_SESSION_PATH + BNOISOLATION_PREFIX_MAXLENGTH] = { 0 };
	UCHAR Buffer[sizeof(OBJECT_NAME_INFORMATION) + MAX_SESSION_PATH * 2] = { 0 };
	POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)Buffer;
	
	*lpLocalLink = NULL;
	*lpGlobalLink = NULL;
	*lpSessionLink = NULL;
	*lpAppContainerNamedObjectsLink = NULL;

	
	memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));

	__try
	{
		
		Status = NtQueryObject(
			BaseNamedObjectDirectory,
			ObjectNameInformation,
			ObjectName,
			sizeof(OBJECT_NAME_INFORMATION) + MAX_SESSION_PATH * 2,
			&ObjectNameLength);

		dprintf(L"[1] NtQueryObject Status: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
		{
			if (Status != STATUS_INFO_LENGTH_MISMATCH)
				leave;

			ObjectNameHeapBuffer = (POBJECT_NAME_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), 0, ObjectNameLength);
			if (!ObjectNameHeapBuffer)
			{
				Status = STATUS_NO_MEMORY;
				leave;
			}

			Status = NtQueryObject(
				BaseNamedObjectDirectory,
				ObjectNameInformation,
				ObjectName,
				ObjectNameLength,
				&ObjectNameLength);

			dprintf(L"[1] Status: 0x%08lx\n", Status);
			if (!NT_SUCCESS(Status))
				leave;
			
			ObjectName = (POBJECT_NAME_INFORMATION)ObjectNameHeapBuffer;
		}

		//
		// Global SymbolicLink Handle
		//

		InitializeObjectAttributes(&ObjectAttributes, &GlobalName, OBJ_OPENIF | OBJ_INHERIT, BnoRootDirectory, NULL);

		Status = NtCreateSymbolicLinkObject(
			&GlobalLinkHandle,
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&GloablObjectDirectoryName);

		dprintf(L"[1] Status: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			leave;

		//
		// Local SymbolicLink Handle
		//
		TargetNameBuffer[0] = L'\0';
		Status = RtlStringCchPrintfW(TargetNameBuffer, MAX_SESSION_PATH + BNOISOLATION_PREFIX_MAXLENGTH, L"%ws\\%ws", ObjectName->Name.Buffer, IsolationPrefix->Buffer);
		if (!NT_SUCCESS(Status))
			leave;

		RtlInitUnicodeString(&LinkTargetName, TargetNameBuffer);
		InitializeObjectAttributes(&ObjectAttributes, &LocalName, OBJ_OPENIF | OBJ_INHERIT, BnoRootDirectory, NULL);

		Status = NtCreateSymbolicLinkObject(
			&LocalLinkHandle,
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&LinkTargetName);

		if (!NT_SUCCESS(Status))
			leave;


		//
		// Session SymbolicLink Handle
		//
		TargetNameBuffer[0] = L'\0';
		Status = RtlStringCchPrintfW(TargetNameBuffer, MAX_SESSION_PATH + BNOISOLATION_PREFIX_MAXLENGTH, L"%ws\\%ws", ObjectName->Name.Buffer, L"Session");
		if (!NT_SUCCESS(Status))
			leave;

		RtlInitUnicodeString(&LinkTargetName, TargetNameBuffer);
		InitializeObjectAttributes(&ObjectAttributes, &SessionName, OBJ_OPENIF | OBJ_INHERIT, BnoRootDirectory, NULL);

		Status = NtCreateSymbolicLinkObject(
			&SessionLinkHandle,
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&LinkTargetName);

		if (!NT_SUCCESS(Status))
			leave;

		//
		// AppContainerNamedObjects SymbolicLink Handle
		//
		TargetNameBuffer[0] = L'\0';
		Status = RtlStringCchPrintfW(TargetNameBuffer, MAX_SESSION_PATH + BNOISOLATION_PREFIX_MAXLENGTH, L"%ws\\%ws", ObjectName->Name.Buffer, L"AppContainerNamedObjects");
		if (!NT_SUCCESS(Status))
			leave;

		RtlInitUnicodeString(&LinkTargetName, TargetNameBuffer);
		InitializeObjectAttributes(&ObjectAttributes, &AppContainerNamedObjectsName, OBJ_OPENIF | OBJ_INHERIT, BnoRootDirectory, NULL);

		Status = NtCreateSymbolicLinkObject(
			&AppContainerNamedObjectsLinkHandle,
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&LinkTargetName);

		if (!NT_SUCCESS(Status))
			leave;
		
		//
		// Symbolic Link Handle Output
		//
		*lpLocalLink = LocalLinkHandle;
		*lpGlobalLink = GlobalLinkHandle;
		*lpSessionLink = SessionLinkHandle;
		*lpAppContainerNamedObjectsLink = AppContainerNamedObjectsLinkHandle;
		LocalLinkHandle = NULL;
		GlobalLinkHandle = NULL;
		SessionLinkHandle = NULL;
		AppContainerNamedObjectsLinkHandle = NULL;

	}
	__finally
	{
		if (ObjectNameHeapBuffer)
			RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, ObjectNameHeapBuffer);

		if (LocalLinkHandle)
			NtClose(LocalLinkHandle);

		if (GlobalLinkHandle)
			NtClose(GlobalLinkHandle);

		if (SessionLinkHandle)
			NtClose(SessionLinkHandle);

		if (AppContainerNamedObjectsLinkHandle)
			NtClose(AppContainerNamedObjectsLinkHandle);
	}
	
	return Status;
}

NTSTATUS BasepCreateBnoIsolationObjectDirectories(IN HANDLE TokenHandle, IN OUT PPS_BNO_ISOLATION_PARAMETERS BnoIsolation)
{
	ULONG HandleListCount = 0;
	NTSTATUS Status = 0;
	HANDLE hToken = NULL;
	HANDLE BaseNamedObjectDirectory = NULL;
	PHANDLE HandleList = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	BnoIsolation->Handles = NULL;
	BnoIsolation->HandleCount = 0;
	
	__try
	{
		if (!TokenHandle)
		{
			Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
			dprintf(L"[0] Status: 0x%08lx\n", Status);
			if (!NT_SUCCESS(Status))
				leave;

			TokenHandle = hToken;
		}

		HandleListCount = 5;
		HandleList = (PHANDLE)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 5 * sizeof(HANDLE));
		if (!HandleList)
		{
			Status = STATUS_NO_MEMORY;
			leave;
		}

		Status = BasepGetNamedObjectDirectoryForToken(TokenHandle, TRUE, 0, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &BaseNamedObjectDirectory);
		dprintf(L"[0] BasepGetNamedObjectDirectoryForToken Status: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			leave;

		InitializeObjectAttributes(&ObjectAttributes, &BnoIsolation->IsolationPrefix, OBJ_OPENIF, BaseNamedObjectDirectory, NULL);
		Status = NtCreateDirectoryObjectEx(&HandleList[0], DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY, &ObjectAttributes, NULL, AlwaysInheritSecurity);
		dprintf(L"[0] NtCreateDirectoryObjectEx Status: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			leave;

		Status = BasepCreateBnoIsolationSymbolicLinks(
			BaseNamedObjectDirectory,
			HandleList[0],
			&BnoIsolation->IsolationPrefix,
			&HandleList[1],
			&HandleList[2],
			&HandleList[3],
			&HandleList[4]);

		dprintf(L"[0] BasepCreateBnoIsolationSymbolicLinks Status: 0x%08lx\n", Status);
		if (!NT_SUCCESS(Status))
			leave;

		BnoIsolation->Handles = HandleList;
		BnoIsolation->HandleCount = 5;
		HandleList = NULL;
	}
	__finally
	{
		if (hToken)
			NtClose(hToken);

		if (BaseNamedObjectDirectory)
			NtClose(BaseNamedObjectDirectory);

		if (HandleList)
		{
			for (DWORD i = 0; i < HandleListCount; i++)
			{
				if (HandleList[i])
					NtClose(HandleList[i]);
			}
			RtlFreeHeap(RtlProcessHeap(), 0, HandleList);
		}
	}

	return Status;
}


NTSTATUS ValidateAppXAliasFallback(LPCWSTR RawBaseImagePath, ExtendedAppExecutionAliasInfo* AppExecutionAliasInfo)
{
	NTSTATUS Status = 0;
	HANDLE AliasFileHandle = NULL;
	HANDLE RawBaseFileHandle = NULL;
	LPWSTR ComparePackageName = NULL;
	LONG ErrorCode = 0;
	FILE_ID_INFO AliasFileIdInfo = { 0 };
	FILE_ID_INFO RawBaseFileIdInfo = { 0 };
	UINT32 PackageBufferLength = 128;
	WCHAR PackageBuffer[128] = { 0 };

	memset(PackageBuffer, 0, sizeof(PackageBuffer));
	AliasFileHandle = CreateFileW(
		AppExecutionAliasInfo->AppAliasBaseImagePath,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (AliasFileHandle == INVALID_HANDLE_VALUE)
	{
		if (NtCurrentTeb()->LastErrorValue > 0)
			return (USHORT)(NtCurrentTeb()->LastErrorValue) | 0xC0070000;
		else
			return NtCurrentTeb()->LastErrorValue;
	}

	RawBaseFileHandle = CreateFileW(
		RawBaseImagePath,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (RawBaseFileHandle != INVALID_HANDLE_VALUE
		&& GetFileInformationByHandleEx(AliasFileHandle, FileIdInfo, &AliasFileIdInfo, sizeof(FILE_ID_INFO))
		&& GetFileInformationByHandleEx(RawBaseFileHandle, FileIdInfo, &RawBaseFileIdInfo, sizeof(FILE_ID_INFO)))
	{
		if (memcmp(AliasFileIdInfo.FileId.Identifier, RawBaseFileIdInfo.FileId.Identifier, sizeof(FILE_ID_128)))
		{
			Status = STATUS_ACCESS_DENIED;
			goto Cleanup;
		}

		if (AppExecutionAliasInfo->PackageFamilyName)
		{
			ComparePackageName = (LPWSTR)AppExecutionAliasInfo->PackageFamilyName;//???
			ErrorCode = GetCurrentPackageFamilyName(&PackageBufferLength, PackageBuffer);
		}
		else if (AppExecutionAliasInfo->AppXPackageName)
		{
			ComparePackageName = (LPWSTR)AppExecutionAliasInfo->AppXPackageName;
			ErrorCode = GetCurrentPackageFullName(&PackageBufferLength, PackageBuffer);

		}
		else
		{
			Status = 0xC007FFFF;
			goto Cleanup;
		}

		//
		// The process has no package identity.
		// 
		if (ErrorCode == APPMODEL_ERROR_NO_PACKAGE)
		{
			Status = STATUS_SUCCESS;
			goto Cleanup;
		}
		else if (ErrorCode == ERROR_SUCCESS)
		{
			if (!_wcsnicmp(PackageBuffer, ComparePackageName, PackageBufferLength))
				Status = STATUS_ACCESS_DENIED;
			goto Cleanup;
		}
	}

	if (NtCurrentTeb()->LastErrorValue > 0)
		Status = (USHORT)(NtCurrentTeb()->LastErrorValue) | 0xC0070000;
	else
		Status = NtCurrentTeb()->LastErrorValue;

Cleanup:
	CloseHandle(AliasFileHandle);
	if (RawBaseFileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(RawBaseFileHandle);

	return Status;
}


NTSTATUS ValidateAppExecutionAliasRedirectPackageIdentity(IN HANDLE KeyHandle, IN ExtendedAppExecutionAliasInfo_New* AppExecutionAliasInfo)
{
	NTSTATUS Status;
	wchar_t* SplitBuffer;
	ULONG ReturnedLength;
	wchar_t* Context;
	WCHAR Buffer[72] = { 0 };

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
		Status = STATUS_ACCESS_DENIED;
	}
	return Status;
}

NTSTATUS GetAppExecutionAliasInfo(
	IN  PWSTR ImagePath,
	IN  PWSTR SpecialAliasRedirectPackages,
	IN  HANDLE TokenHandle,
	IN  PVOID AliasHeap,
	OUT ExtendedAppExecutionAliasInfo** ulppExtendedAppExecutionAliasInfo)
{
	LPWSTR AliasFullPath = NULL;
	NTSTATUS ErrorStatus = 0;
	DWORD Length = 0;

	//
	// TEST
	//
	if (GetAppExecutionAliasPathEx && IsGetAppExecutionAliasPathExPresent())
	{
		ErrorStatus = GetAppExecutionAliasPathEx(
			ImagePath,
			SpecialAliasRedirectPackages,
			TokenHandle,
			NULL,
			&Length);

		if ((USHORT)ErrorStatus == ERROR_INSUFFICIENT_BUFFER)
		{
			AliasFullPath = (LPWSTR)RtlAllocateHeap(AliasHeap, 0, 2 * static_cast<SIZE_T>(Length));
			if (!AliasFullPath)
				return STATUS_NO_MEMORY;
			ErrorStatus = GetAppExecutionAliasPathEx(
				ImagePath,
				SpecialAliasRedirectPackages,
				TokenHandle,
				AliasFullPath,
				&Length);
		}
	}
	else if (IsGetAppExecutionAliasPathPresent() && !SpecialAliasRedirectPackages)
	{
		ErrorStatus = GetAppExecutionAliasPath(
			ImagePath,
			TokenHandle,
			NULL,
			&Length);

		if ((USHORT)ErrorStatus == ERROR_INSUFFICIENT_BUFFER)
		{
			AliasFullPath = (LPWSTR)RtlAllocateHeap(AliasHeap, 0, 2 * static_cast<SIZE_T>(Length));
			if (!AliasFullPath)
				return STATUS_NO_MEMORY;

			ErrorStatus = GetAppExecutionAliasPath(
				ImagePath,
				TokenHandle,
				AliasFullPath,
				&Length);
		}
	}
	else
	{
		return STATUS_NOT_IMPLEMENTED;
	}
	if (ErrorStatus)
		ErrorStatus |= 0xC0070000;

	if (NT_SUCCESS(ErrorStatus))
		ErrorStatus = LoadAppExecutionAliasInfoEx(AliasFullPath, TokenHandle, ulppExtendedAppExecutionAliasInfo);

	dprintf(L"LoadAppExecutionAliasInfoEx : 0x%08lx\n", ErrorStatus);
	if (AliasFullPath)
		RtlFreeHeap(AliasHeap, 0, AliasFullPath);
	return ErrorStatus;
}

NTSTATUS LoadAppExecutionAliasInfoForExecutable(
	IN  HANDLE KeyHandle,
	IN  PWSTR Win32ImagePath,
	IN  HANDLE TokenHandle,
	IN  HANDLE HeapHandle,
	OUT	ExtendedAppExecutionAliasInfo** lppAppExecutionAliasInfo)
{
	NTSTATUS Status = 0;
	PWSTR AliasPackagesBuffer = NULL;
	ULONG AliasPackagesBufferSize = 0;
	DWORD AliasRedirectEnabled = 0;
	ULONG ReturnedLength = 0;
	WCHAR Buffer[4] = { 0 };
	ExtendedAppExecutionAliasInfo* SpecialAppAliasInfo = NULL;
	wchar_t* SpecialAliasRedirectPackages = NULL;
	wchar_t* Context = NULL;
	

	AliasRedirectEnabled = 0;
	ReturnedLength = 0;
	if (!IsLoadAppExecutionAliasInfoExPresent())
		return STATUS_NOT_IMPLEMENTED;

	if (!KeyHandle)
		return GetAppExecutionAliasInfo(
			Win32ImagePath,
			NULL,
			TokenHandle,
			HeapHandle,
			lppAppExecutionAliasInfo);

	Status = LdrQueryImageFileKeyOption(
		KeyHandle,
		L"AppExecutionAliasRedirect",
		REG_DWORD,
		(LPCWSTR)&AliasRedirectEnabled,
		sizeof(DWORD),
		NULL);

	if (!NT_SUCCESS(Status))
		return Status;

	if (AliasRedirectEnabled != TRUE)
		return STATUS_NOT_FOUND;

	Status = LdrQueryImageFileKeyOption(
		KeyHandle,
		L"AppExecutionAliasRedirectPackages",
		REG_SZ,
		Buffer,
		4,
		&ReturnedLength);

	if (Status == STATUS_BUFFER_OVERFLOW)
	{
		AliasPackagesBufferSize = ReturnedLength + sizeof(UNICODE_NULL);
		AliasPackagesBuffer = (PWSTR)RtlAllocateHeap(HeapHandle, 0, AliasPackagesBufferSize);
		if (!AliasPackagesBuffer)
			return STATUS_NO_MEMORY;

		Status = LdrQueryImageFileKeyOption(
			KeyHandle,
			L"AppExecutionAliasRedirectPackages",
			REG_SZ,
			AliasPackagesBuffer,
			AliasPackagesBufferSize,
			&ReturnedLength);

		Buffer[ReturnedLength / sizeof(WCHAR)] = NULL;
	}
	else if (NT_SUCCESS(Status) && (ReturnedLength != 4 || Buffer[0] != '*' || Buffer[1]))
	{
		//
		// Somebody would like do something dangerous
		//
		Status = STATUS_ACCESS_DENIED;
	}

	if (!NT_SUCCESS(Status))
	{
		if (AliasPackagesBuffer)
			RtlFreeHeap(HeapHandle, 0, AliasPackagesBuffer);
		return Status;
	}

	if (!AliasPackagesBuffer)
		return GetAppExecutionAliasInfo(
			Win32ImagePath,
			NULL,
			TokenHandle,
			HeapHandle,
			lppAppExecutionAliasInfo);
	Context = NULL;
	SpecialAliasRedirectPackages = wcstok_s(AliasPackagesBuffer, L";", &Context);
	do
	{
		if (!SpecialAliasRedirectPackages)
		{
			RtlFreeHeap(HeapHandle, 0, AliasPackagesBuffer);
			return STATUS_NOT_FOUND;
		}

		SpecialAppAliasInfo = NULL;

		if (GetAppExecutionAliasInfo(
			Win32ImagePath,
			SpecialAliasRedirectPackages,// SpecialAliasRedirectPackages in
			TokenHandle,
			HeapHandle,
			&SpecialAppAliasInfo) >= 0)
		{
			if (!SpecialAppAliasInfo)
				continue;

			if (CompareStringOrdinal(SpecialAliasRedirectPackages, -1, SpecialAppAliasInfo->AppExecutionAliasRedirectPackages, -1, TRUE) == CSTR_EQUAL)
			{
				Status = 0;
				*lppAppExecutionAliasInfo = SpecialAppAliasInfo;
				break;
			}
		}
		if (SpecialAppAliasInfo)
			FreeAppExecutionAliasInfoEx(SpecialAppAliasInfo);

		SpecialAliasRedirectPackages = wcstok_s(0, L";", &Context);
	} while (true);
	
	return Status;
}

NTSTATUS BasepUpdateProcessParametersField(
	IN HANDLE ProcessHandle,
	IN LPVOID* ValuePointer,//ULONGLONG*
	IN SIZE_T NumberOfBytesToWrite,
	IN LPVOID* Wow64ValuePointer,//ULONG*
	IN ULONGLONG ProcessParametersOffset,
	IN ULONG ProcessParametersWow64Offset,
	IN PPS_CREATE_INFO CreateInfo)
{
	NTSTATUS Status = 0;
	ULONGLONG* lpFieldValue = 0;
	ULONG* lpWow64FieldValue = 0;

	if (NumberOfBytesToWrite == 4)
	{
		lpFieldValue = (ULONGLONG *)ValuePointer;
		lpWow64FieldValue = (ULONG*)Wow64ValuePointer;
	}
	else
	{
		lpFieldValue = (ULONGLONG*)ValuePointer;
		lpWow64FieldValue = (ULONG*)ValuePointer;
	}

	Status = NtWriteVirtualMemory(
		ProcessHandle,
		(PVOID)(CreateInfo->SuccessState.UserProcessParametersNative + ProcessParametersOffset),
		lpFieldValue,
		NumberOfBytesToWrite,
		NULL);

	if (!NT_SUCCESS(Status))
		return Status;

	if (CreateInfo->SuccessState.UserProcessParametersWow64)
	{
		Status = NtWriteVirtualMemory(
			ProcessHandle,
			(PVOID)(CreateInfo->SuccessState.UserProcessParametersWow64 + (ULONGLONG)ProcessParametersWow64Offset),
			lpWow64FieldValue,
			sizeof(ULONG),
			NULL);
	}

	return Status;
}

PVOID BasepIsRealtimeAllowed(
	IN BOOLEAN LeaveEnabled,
	IN BOOLEAN Impersonating)
{
	ULONG Privilege = SE_INC_BASE_PRIORITY_PRIVILEGE;
	PVOID State = 0;
	NTSTATUS Status = 0;
	Status = RtlAcquirePrivilege(&Privilege, 1, Impersonating ? RTL_ACQUIRE_PRIVILEGE_REVERT: 0, &State);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	if (!LeaveEnabled) {
		RtlReleasePrivilege(State);
		State = (PVOID)1;
	}
	return State;
}

VOID BasepAddToOrUpdateAttributesList(
	IN PPS_ATTRIBUTE_LIST AttributeListSource,
	IN ULONG AttributeListSourceCount,
	IN OUT PPS_ATTRIBUTE_LIST AttributeListDest,
	IN OUT PULONG AttributeListDestCount)
{
	PS_ATTRIBUTE* Attributes = NULL;
	DWORD i = 0;

	Attributes = AttributeListSource->Attributes;
	while (AttributeListSourceCount)
	{
		
		if (*AttributeListDestCount)
		{
			// 遍历
			for (i = 0; i < *AttributeListDestCount; i++)
			{
				if (AttributeListDest->Attributes[i].Attribute == Attributes->Attribute)
				{
					// 不检查 Attributes 大小
					AttributeListDest->Attributes[i].Value = Attributes->Value;
					break;
				}
			}
		}
		
		if(!*AttributeListDestCount || i >= *AttributeListDestCount)
		{
			(*AttributeListDestCount)++;
			AttributeListDest->Attributes[*AttributeListDestCount].Attribute = Attributes->Attribute;
			AttributeListDest->Attributes[*AttributeListDestCount].Size = Attributes->Size;
			AttributeListDest->Attributes[*AttributeListDestCount].ReturnLength = Attributes->ReturnLength;
			AttributeListDest->Attributes[*AttributeListDestCount].Value = Attributes->Value;
		}

		Attributes++;
		AttributeListSourceCount--;
	}

	return;
}

NTSTATUS BasepFreeActivationTokenInfo(PACTIVATION_TOKEN_INFO lpActivationTokenInfo)
{
	if (lpActivationTokenInfo->ActivationTokenHandle)
		NtClose(lpActivationTokenInfo->ActivationTokenHandle);

	if (lpActivationTokenInfo->PackageBnoIsolationPrefix)
		RtlFreeHeap(RtlProcessHeap(), 0, lpActivationTokenInfo->PackageBnoIsolationPrefix);

	*lpActivationTokenInfo = { 0 };
	return 0;
}

namespace wil::details
{
	VOID CloseWintrustData(PWINTRUST_DATA pWinTrustData)
	{
		GUID CloseActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		pWinTrustData->dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &CloseActionGuid, pWinTrustData);
		return;
	}
}
// 小子、老表们，还记得这个函数很容易被欺骗不？
// 如果只针对 AppX Package 检查的话，感觉不好欺骗，也没什么用处
NTSTATUS AppXCheckPplSupport(LPCWSTR szFilePath, BOOL* IsPplSupported)
{
	CERT_CHAIN_PARA CertChainPara = { 0 };
	WINTRUST_DATA WinTrustData = { 0 };
	WINTRUST_FILE_INFO FileData = { 0 };
	WTD_GENERIC_CHAIN_POLICY_DATA PolicyData = { 0 };
	WTD_GENERIC_CHAIN_POLICY_CREATE_INFO PolicyCreateInfo = { 0 };
	const GUID WinVerifyGuid = WINTRUST_ACTION_GENERIC_CHAIN_VERIFY;
	static const char* EnhancedOidIdentifier = szOID_PROTECTED_PROCESS_LIGHT_SIGNER;

	*IsPplSupported = FALSE;
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.fdwRevocationChecks = FALSE;
	WinTrustData.pFile = &FileData;
	WinTrustData.cbStruct = sizeof(WinTrustData);
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.pPolicyCallbackData = &PolicyData;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

	FileData.cbStruct = sizeof(FileData);
	FileData.hFile = NULL;
	FileData.pcwszFilePath = szFilePath;

	PolicyData.cbSize = sizeof(PolicyData);
	PolicyData.pSignerChainInfo = &PolicyCreateInfo;

	PolicyCreateInfo.cbSize = sizeof(PolicyCreateInfo);
	PolicyCreateInfo.pvReserved = 0;
	PolicyCreateInfo.pChainPara = &CertChainPara;
	PolicyCreateInfo.hChainEngine = HCCE_LOCAL_MACHINE;
	PolicyCreateInfo.dwFlags = CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY | CERT_CHAIN_REVOCATION_CHECK_END_CERT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;//CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG;

	CertChainPara.cbSize = sizeof(CertChainPara);
	CertChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	CertChainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
	CertChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR*)&EnhancedOidIdentifier;
	
	if(!WinVerifyTrust((HWND)INVALID_HANDLE_VALUE,(GUID*)&WinVerifyGuid, &WinTrustData))
		*IsPplSupported = TRUE;

	wil::details::CloseWintrustData(&WinTrustData);

	return STATUS_SUCCESS;;
}

NTSTATUS BasepCheckPplSupport(LPCWSTR szFilePath, BOOL* IsPplSupported)
{
	return AppXCheckPplSupport(szFilePath, IsPplSupported);
}