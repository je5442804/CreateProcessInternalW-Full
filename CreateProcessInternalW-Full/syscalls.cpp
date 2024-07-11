#define _USE_FULL_PROC_THREAD_ATTRIBUTE
#define UMDF_USING_NTSTATUS
#include "syscalls.hpp"
#include "structs.hpp"
#include <stdio.h>

PBASE_STATIC_SERVER_DATA BaseStaticServerData;
ULONG KernelBaseGlobalData;
USHORT OSBuildNumber;
HANDLE ConhostConsoleHandle;

AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

ApiSetCheckFunction IsBasepConstructSxsCreateProcessMessagePresent = 0;
ApiSetCheckFunction IsBasepInitAppCompatDataPresent = 0;
ApiSetCheckFunction IsBasepAppXExtensionPresent = 0;
ApiSetCheckFunction IsBasepCheckPplSupportPresent = 0;
ApiSetCheckFunction IsBasepGetPackagedAppInfoForFilePresent = 0;
ApiSetCheckFunction IsBasepGetAppCompatDataPresent = 0;
ApiSetCheckFunction IsBaseCheckElevationPresent = 0;
ApiSetCheckFunction IsBaseWriteErrorElevationRequiredEventPresent = 0;
ApiSetCheckFunction IsBasepCheckWebBladeHashesPresent = 0;
ApiSetCheckFunction IsBasepQueryModuleChpeSettingsPresent = 0;
ApiSetCheckFunction IsBasepIsProcessAllowedPresent = 0;
ApiSetCheckFunction IsBasepQueryAppCompatPresent = 0;
ApiSetCheckFunction IsBasepAppContainerEnvironmentExtensionPresent = 0;
ApiSetCheckFunction IsBasepCheckWinSaferRestrictionsPresent = 0;
ApiSetCheckFunction IsBasepFreeAppCompatDataPresent = 0;
ApiSetCheckFunction IsBasepReleaseSxsCreateProcessUtilityStructPresent = 0;
ApiSetCheckFunction IsBasepProcessInvalidImagePresent = 0;
ApiSetCheckFunction IsBaseElevationPostProcessingPresent = 0;
ApiSetCheckFunction IsBaseDestroyVDMEnvironmentPresent = 0;
ApiSetCheckFunction IsBaseUpdateVDMEntryPresent = 0;
ApiSetCheckFunction IsBaseIsDosApplicationPresent = 0;
ApiSetCheckFunction IsNtVdm64CreateProcessInternalWPresent = 0;
ApiSetCheckFunction IsRaiseInvalid16BitExeErrorPresent = 0;

ApiSetCheckFunction IsCheckAppXPackageBreakawayPresent = 0;
ApiSetCheckFunction IsGetAppExecutionAliasPathPresent = 0;
ApiSetCheckFunction IsLoadAppExecutionAliasInfoExPresent = 0;
ApiSetCheckFunction IsGetAppExecutionAliasPathExPresent = 0;


BasepConvertWin32AttributeList_ BasepConvertWin32AttributeList_inline;
BasepCreateLowBox_ BasepCreateLowBox;

BuildSubSysCommandLine_ BuildSubSysCommandLine;
BasepGetConsoleHost_ BasepGetConsoleHost;
//LoadAppExecutionAliasInfoForExecutable_ LoadAppExecutionAliasInfoForExecutable;

GetPackageFullNameFromToken__ GetPackageFullNameFromToken_;

KernelBaseGetGlobalData_ KernelBaseGetGlobalData;
BaseFormatObjectAttributes_ BaseFormatObjectAttributes;
CheckAppXPackageBreakaway_ CheckAppXPackageBreakaway;
LoadAppExecutionAliasInfoEx_ LoadAppExecutionAliasInfoEx;
GetAppExecutionAliasPath_ GetAppExecutionAliasPath;
GetAppExecutionAliasPathEx_ GetAppExecutionAliasPathEx;

CompletePackagedProcessCreationEx_ CompletePackagedProcessCreationEx;
CompleteAppExecutionAliasProcessCreationEx_ CompleteAppExecutionAliasProcessCreationEx;
PerformAppxLicenseRundownEx_ PerformAppxLicenseRundownEx;
FreeAppExecutionAliasInfoEx_ FreeAppExecutionAliasInfoEx;
GetEmbeddedImageMitigationPolicy_ GetEmbeddedImageMitigationPolicy;
BaseSetLastNTError_ BaseSetLastNTError;
BasepAppXExtension_ BasepAppXExtension;
BasepGetPackagedAppInfoForFile_ BasepGetPackagedAppInfoForFile;
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
BasepGetPackageActivationTokenForSxS2_ BasepGetPackageActivationTokenForSxS2;
BaseElevationPostProcessing_ BaseElevationPostProcessing;
BasepPostSuccessAppXExtension_ BasepPostSuccessAppXExtension;
BasepFinishPackageActivationForSxS_ BasepFinishPackageActivationForSxS;
BasepReleasePackagedAppInfo_ BasepReleasePackagedAppInfo;
BaseDestroyVDMEnvironment_ BaseDestroyVDMEnvironment;

NtVdm64CreateProcessInternalW_ NtVdm64CreateProcessInternalW = NULL;

HMODULE Ntdll;
HMODULE Kernel32;
HMODULE KernelBase;
DWORD SizeOfNtdll;
DWORD SizeOfKernel32;
DWORD SizeOfKernelBase = 0;
USHORT NtdllRevision;
USHORT NtdllBuildNumber;

//PVOID Ntdll, DWORD SizeOfNtdll, PVOID Kernel32, DWORD SizeofKernel32, PVOID KernelBase, DWORD SizeofKernelBase
int GetGloablVariable()
{

    //PVOID tempaddress = 0;
    //PVOID BaseStaticServerDataAddress = 0;
    /*
    for (int i = 0x100; i < SizeofKernelBase - 0x100; i++)
    {
        BYTE signaturecode3[] = { 0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00,0x48,0x8B,0x88,0x98,0x00,0x00,0x00,0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00,0x48,0x8B,0x51,0x08,0x48,0x2B,0x90,0x80,0x03,0x00,0x00 };

        BYTE signaturecode4[] = { 0x65,0x48,0x8B,0x0C,0x25,0x60,0x00,0x00,0x00, 0x4C,0x8D,0x0D };

        if (!BaseStaticServerData && !memcmp(signaturecode3, (char*)KernelBase + i, sizeof(signaturecode3)))
        {
            BYTE temp3[] = { 0x48,0x89,0x15 };
            for (int j = sizeof(signaturecode3); j <= 0x50; j++)
            {
                if (!memcmp(temp3, (char*)KernelBase + i + j, sizeof(temp3)))
                {
                    tempaddress = (char*)KernelBase + i + j + 3;
                    BaseStaticServerDataAddress = (char*)tempaddress + 4 + *((DWORD*)(tempaddress));
                    wprintf(L"[+] Get BaseStaticServerData Address: 0x%p\n", BaseStaticServerDataAddress);
                    BaseStaticServerData = *(PVOID*)BaseStaticServerDataAddress;
                    wprintf(L"[+] BaseStaticServerData: 0x%p\n", BaseStaticServerData);
                    break;
                }
            }
        }

    }
    */
    if (!ConhostConsoleHandle)
    {
        ConhostConsoleHandle = (BaseGetConsoleReference_)GetProcAddress(KernelBase, "BaseGetConsoleReference")();
    }

    BaseStaticServerData = BASE_SHARED_SERVER_DATA;

    if (BaseStaticServerData)
        dprintf(L"[+] BaseStaticServerData: 0x%p\n", BaseStaticServerData);

    return 0;
}

//PVOID KernelBase, DWORD SizeofKernelBase
void GetUnexportFunction(DWORD SizeofKernelBase)
{
    //BYTE signaturecode0[] = { 0x48,0x83,0xEC,0x20,0x45,0x33,0xC0,0xC7,0x40,0x10,0x0E,0x00,0x00,0x00 };//BasepIsRealtimeAllowed
    //BYTE signaturecode1[] = { 0x0F,0xB7,0x11,0x4C,0x8B,0xC1,0xD1,0xEA };//BasepAdjustApplicationPath              0x75 0x07, 0xeb, 0x0a 
    BYTE signaturecode2[] = { 0x85, 0xC0 };
    BYTE signaturecode3[] = { 0x48,0x83,0xec,0x28,0x8b,0x0d,  0x00,0x83,0xf9,0x01,0x75,0x04,0x8a,0xc1,0xeb,0x36,0x83,0xf9,0x02 };
    //BYTE signaturecode4[] = { 0x48,0x89,0x5C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0x70,0xFF,0xFF,0xFF };//ValidateAppXAliasFallback

    //BYTE signaturecode5[] = { 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x58, 0x4C, 0x8B, 0x8D };//BasepConvertWin32AttributeList


    BYTE signaturecode5[] = { 0x00, 0x00, 0xB2, 0x01 };

    // 0x38 0x??
    BYTE signaturecode6[] = { 0XCC,0xCC,0x48,0x85,0xC9,0x74,0x38,0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57 }; //BasepFreeBnoIsolationParameter
    //BYTE signaturecode7[] = { 0xCC,0x48,0x89,0x5C,0x24,0x08,0x45,0x8B,0x19,0x85,0xD2,0x74,0x5B,0x4C,0x8D,0x51,0x08,0x8B,0xD2 };//BasepAddToOrUpdateAttributesList
    //BYTE signaturecode8[] = { 0xCC,0x48,0x89,0x5C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x56,0x48,0x8B,0xEC,0x48,0x83,0xEC,0x70 };//BasepCreateBnoIsolationObjectDirectories
    //BYTE signaturecode9[] = { 0x48,0x8D,0xAC,0x24,0x78,0xFC,0xFF,0xFF };//BasepCreateProcessParameters
    BYTE signaturecode10[] = { 0xC7,0x45,0xD0,0x08,0x00,0x0A,0x00 }; //BuildSubSysCommandLine
    BYTE signaturecode11[] = { 0x41,0xb9,0x08,0x00,0x00,0x00,0x48,0x83,0xc9,0xff }; //BasepGetConsoleHost
    //BYTE signaturecode12[] = { 0x48,0x8b,0xf1,0x49,0x83,0xf8,0x04 };//BasepUpdateProcessParametersField
    //BYTE signaturecode13[] = { 0x66,0x83,0xF8,0x7A };//LoadAppExecutionAliasInfoForExecutable

    PVOID CreateAppContainerToken = (PVOID)GetProcAddress(KernelBase, "CreateAppContainerToken");
    BasepCreateLowBox = (BasepCreateLowBox_)((char*)CreateAppContainerToken + 9 + *(DWORD*)((char*)CreateAppContainerToken + 5));
    dprintf(L"[+] Got Unexported BasepCreateLowBox: 0x%p\n", BasepCreateLowBox);


    PVOID TempAddress2 = (PVOID)GetProcAddress(KernelBase, "AppPolicyGetShowDeveloperDiagnostic");
    for (int j = 0; j <= 0x100; j++)
    {
        PVOID Address = (char*)TempAddress2 + j;
        if (*(UCHAR*)(Address) == 0xE8 && !memcmp(signaturecode2, (char*)Address + 5, sizeof(signaturecode2)))
        {
            Address = (char*)Address + 1;
            TempAddress2 = (char*)Address + sizeof(ULONG);
            ULONG RVA = *(ULONG*)Address + (ULONG)(ULONG_PTR)TempAddress2;
            Address = (PVOID)((ULONG_PTR)RVA + PtrHigh32(TempAddress2));// GetAppModelPolicy

            BYTE TempCode[] = { 0x0D,0x00,0x00,0x00,0x10 };
            for (int i = 0; i <= 0x40; i++)
            {
                if (!memcmp(TempCode, (char*)Address + i, sizeof(TempCode)))
                {
                    TempAddress2 = (char*)Address + i;
                    Address = (char*)Address + i - sizeof(ULONG);
                    RVA = *(ULONG*)Address + (ULONG)(ULONG_PTR)TempAddress2;
                    AppModelPolicy_GetPolicy_Internal = (AppModelPolicy_GetPolicy_Internal_)((ULONG_PTR)RVA + PtrHigh32(TempAddress2));
                    dprintf(L"[+] Got Unexported AppModelPolicy_GetPolicy_Internal: 0x%p\n", AppModelPolicy_GetPolicy_Internal);// Warning! Two of AppModelPolicy_GetPolicy_Internal APIs in different address!
                    break;
                }
            }
            break;
        }
    }

    for (DWORD i = 0; i < SizeofKernelBase - 0x100; i++)
    {
        if (!memcmp(signaturecode3, (char*)KernelBase + i, 6) && !memcmp((char*)signaturecode3 + 6, (char*)KernelBase + i + 9, 13))
        {
            BYTE temp3[] = { 0x48,0x8D,0x54,0x24,0x30,0xC6,0x44,0x24,0x30,0x00,0x48,0x8D,0x0D };
            //BYTE temp4[] = { 0x00,0xE8,0x6A,0xFF,0xFF,0xFF,0x85,0xC0,0x78 };
            for (int j = 0x16; j <= 0x24; j++)
            {
                // 应该换个好点的，正常的方法来获取地址呃呃呃
                // RtlIsApiSetImplemented
                if (!memcmp(temp3, (char*)KernelBase + i + j, sizeof(temp3)))
                {
                    ULONG_PTR Address = (ULONG_PTR)((char*)KernelBase + i + j + 13 + sizeof(ULONG));
                    ULONG RVA = (ULONG)(Address)+*(ULONG*)((char*)KernelBase + i + j + 13);
                    // (char*)KernelBase + i + j + 17 + *(DWORD*)((char*)KernelBase + i + j + 13)
                    PUNICODE_STRING ApiSetPresenceAddress = (PUNICODE_STRING)((ULONG_PTR)RVA + PtrHigh32(Address));
                    //dprintf(L"Length: %ld, Name: %ls -- Function = 0x%p\n", ApiSetPresenceAddress->Length, ApiSetPresenceAddress->Buffer, (char*)KernelBase + i);
                    if (!IsCheckAppXPackageBreakawayPresent && ApiSetPresenceAddress->Length == 68 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-appmodel-daxcore-l1-1-0", 68))
                    {
                        IsCheckAppXPackageBreakawayPresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[+] IsCheckAppXPackageBreakawayPresent: 0x%p\n", IsCheckAppXPackageBreakawayPresent);
                        break;
                    }
                    if (!IsLoadAppExecutionAliasInfoExPresent && ApiSetPresenceAddress->Length == 88 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-appmodel-appexecutionalias-l1-1-0", 88))
                    {
                        IsLoadAppExecutionAliasInfoExPresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[*] IsLoadAppExecutionAliasInfoExPresent: 0x%p\n", IsLoadAppExecutionAliasInfoExPresent);
                        break;
                    }

                    if (!IsGetAppExecutionAliasPathPresent && ApiSetPresenceAddress->Length == 88 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-appmodel-appexecutionalias-l1-1-2", 88))
                    {
                        IsGetAppExecutionAliasPathPresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[*] IsGetAppExecutionAliasPathPresent: 0x%p\n", IsGetAppExecutionAliasPathPresent);
                        break;
                    }

                    if (!IsGetAppExecutionAliasPathExPresent && ApiSetPresenceAddress->Length == 88 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-appmodel-appexecutionalias-l1-1-5", 88))
                    {
                        IsGetAppExecutionAliasPathExPresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[*] IsGetAppExecutionAliasPathExPresent: 0x%p\n", IsGetAppExecutionAliasPathExPresent);
                        break;
                    }

                    if (!IsBasepProcessInvalidImagePresent && ApiSetPresenceAddress->Length == 84 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-kernelbase-processthread-l1-1-0", 84))
                    {
                        IsBasepProcessInvalidImagePresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[+] IsBasepProcessInvalidImagePresent: 0x%p\n", IsBasepProcessInvalidImagePresent);
                        break;
                    }

                    if (!IsBasepGetPackagedAppInfoForFilePresent && ApiSetPresenceAddress->Length == 84 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-kernelbase-processthread-l1-1-2", 84))
                    {
                        IsBasepGetPackagedAppInfoForFilePresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[+] IsBasepGetPackagedAppInfoForFilePresent: 0x%p\n", IsBasepGetPackagedAppInfoForFilePresent);
                        break;
                    }

                    if (!IsBasepCheckPplSupportPresent && ApiSetPresenceAddress->Length == 84 && !memcmp(ApiSetPresenceAddress->Buffer, L"ext-ms-win-kernelbase-processthread-l1-1-3", 84))
                    {
                        IsBasepCheckPplSupportPresent = (ApiSetCheckFunction)((char*)KernelBase + i);
                        dprintf(L"[+] IsBasepCheckPplSupportPresent: 0x%p\n", IsBasepCheckPplSupportPresent);
                        break;
                    }
                }
            }
        }
      

        if (!BasepConvertWin32AttributeList_inline && !memcmp(signaturecode5, (char*)KernelBase + i, sizeof(signaturecode5)))
        {
            BYTE Temp5[] = { 0x89, 0x24 };
            ULONG Count = 0;
            for (int j = 0; j <= 0x100; j++)
            {
                PVOID TempAddress = (char*)KernelBase + i - j;
                if (!memcmp(Temp5, TempAddress, 1) && !memcmp(Temp5 + 1, (char*)TempAddress + 2, 1))
                {
                    Count++;
                }
            }
            if (Count >= 12)
            {

                ULONG_PTR Address = (ULONG_PTR)((char*)KernelBase + i + 8 + sizeof(ULONG));
                ULONG RVA = (ULONG)(Address)+*(ULONG*)((char*)KernelBase + i + 8);
                BasepConvertWin32AttributeList_inline = (BasepConvertWin32AttributeList_)(RVA + PtrHigh32(Address));
                dprintf(L"[+] Got Unexported BasepConvertWin32AttributeList: 0x%p\n", BasepConvertWin32AttributeList_inline);
            }

            i += 0x100;
        }

        if (!BuildSubSysCommandLine && !memcmp(signaturecode10, (char*)KernelBase + i, sizeof(signaturecode10)))
        {
            for (int j = 0; j <= 0x24; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 3))
                {
                    BuildSubSysCommandLine = (BuildSubSysCommandLine_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BuildSubSysCommandLine: 0x%p\n", BuildSubSysCommandLine);
                    break;
                }
            }
        }

        if (!BasepGetConsoleHost && !memcmp(signaturecode11, (char*)KernelBase + i, sizeof(signaturecode11)))
        {
            for (int j = 0; j <= 0x24; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 3))
                {
                    BasepGetConsoleHost = (BasepGetConsoleHost_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BasepGetConsoleHost: 0x%p\n", BasepGetConsoleHost);
                    break;
                }
            }
        }

        /*
        if (OSBuildNumber >= 21313 && !LoadAppExecutionAliasInfoForExecutable && !memcmp(signaturecode13, (char*)KernelBase + i, sizeof(signaturecode13)))
        {
            for (int j = 0; j <= 0x80; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 3))
                {
                    LoadAppExecutionAliasInfoForExecutable = (LoadAppExecutionAliasInfoForExecutable_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported LoadAppExecutionAliasInfoForExecutable: 0x%p\n", LoadAppExecutionAliasInfoForExecutable);
                    break;
                }
            }

        }
        */
    }

    if (!IsBasepGetPackagedAppInfoForFilePresent)
        IsBasepGetPackagedAppInfoForFilePresent = IsBasepProcessInvalidImagePresent;
    if (!IsGetAppExecutionAliasPathExPresent)
        IsGetAppExecutionAliasPathExPresent = IsBasepProcessInvalidImagePresent;
    if (!IsBasepCheckPplSupportPresent)
        IsBasepCheckPplSupportPresent = IsBasepProcessInvalidImagePresent;
}
BOOL NoMore()
{
    PPEB_LDR_DATA Ldr = NtCurrentPeb()->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
    PVOID DllBase = NULL;
    //PVOID ntdll = 0;
    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    //DWORD SizeOfNtdll = 0;
    //PVOID Kernel32 = 0;
    //DWORD SizeofKernel32 = 0;
    //PVOID KernelBase = 0;
    //DWORD SizeofKernelBase = 0;
    for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink; LdrEntry->DllBase != NULL; LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->InLoadOrderLinks.Flink)
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;

        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) == 'nrek')
        {
            if ((*(ULONG*)(DllName + 4) | 0x20202020) == '23le')
            {
                //wprintf(L"OK Kernel32: %p\n", DllBase);
                Kernel32 = (HMODULE)DllBase;
                SizeOfKernel32 = NtHeaders->OptionalHeader.SizeOfImage;
            }
            if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'able')
            {
                //wprintf(L"OK KernelBase: %p\n", DllBase);
                KernelBase = (HMODULE)DllBase;
                SizeOfKernelBase = NtHeaders->OptionalHeader.SizeOfImage;
            }
        }
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
        {
            //wprintf(L"OK Ntdll: %p\n", DllBase);
            Ntdll = (HMODULE)DllBase;
            SizeOfNtdll = NtHeaders->OptionalHeader.SizeOfImage;
            ExportDirectoryNtdll = ExportDirectory;
        }
    }
    DllBase = 0;
    ExportDirectory = ExportDirectoryNtdll;
    if (!ExportDirectory)
        return FALSE;
    OSBuildNumber = NtCurrentPeb()->OSBuildNumber;
    PVOID Address = FindResourceW(Ntdll, MAKEINTRESOURCEW(1), RT_VERSION);
    if (Address)
    {
        *(USHORT*)&Address = *(USHORT*)Address;
        //wprintf(L"0x%p ---------------------------------------", Address);
        NtdllRevision = *(USHORT*)((char*)Address + 0x34);
        NtdllBuildNumber = *(USHORT*)((char*)Address + 0x36);
    }

    GetGloablVariable();
    GetUnexportFunction(SizeOfKernelBase);

    return TRUE;
}


void init2()
{
    HMODULE ntvdm = LoadLibraryW(L"ntvdm64.dll");
    NtVdm64CreateProcessInternalW = ntvdm ? (NtVdm64CreateProcessInternalW_)GetProcAddress(ntvdm, "NtVdm64CreateProcessInternalW") : NULL;
}
void init()
{
    NoMore();//Init  ovo..
    HMODULE AppExecutionAlias = LoadLibraryW(L"ApiSetHost.AppExecutionAlias.dll");
    HMODULE daxexec = LoadLibraryW(L"daxexec.dll");
    HMODULE sechost = GetModuleHandleW(L"sechost.dll");
    if (AppExecutionAlias && daxexec && sechost)
    {

        CheckAppXPackageBreakaway = (CheckAppXPackageBreakaway_)GetProcAddress(daxexec, "CheckAppXPackageBreakaway");
        LoadAppExecutionAliasInfoEx = (LoadAppExecutionAliasInfoEx_)GetProcAddress(AppExecutionAlias, "LoadAppExecutionAliasInfoEx");
        GetAppExecutionAliasPath = (GetAppExecutionAliasPath_)GetProcAddress(AppExecutionAlias, "GetAppExecutionAliasPath");
        GetAppExecutionAliasPathEx = (GetAppExecutionAliasPathEx_)GetProcAddress(AppExecutionAlias, "GetAppExecutionAliasPathEx");

        CompletePackagedProcessCreationEx = (CompletePackagedProcessCreationEx_)GetProcAddress(AppExecutionAlias, "CompletePackagedProcessCreationEx");
        CompleteAppExecutionAliasProcessCreationEx = (CompleteAppExecutionAliasProcessCreationEx_)GetProcAddress(AppExecutionAlias, "CompleteAppExecutionAliasProcessCreationEx");
        PerformAppxLicenseRundownEx = (PerformAppxLicenseRundownEx_)GetProcAddress(AppExecutionAlias, "PerformAppxLicenseRundownEx");
        FreeAppExecutionAliasInfoEx = (FreeAppExecutionAliasInfoEx_)GetProcAddress(AppExecutionAlias, "FreeAppExecutionAliasInfoEx");
        GetEmbeddedImageMitigationPolicy = (GetEmbeddedImageMitigationPolicy_)GetProcAddress(sechost, "GetEmbeddedImageMitigationPolicy");
    }
    else
    {
        wprintf(L"[-] Error in Module Load...\n");
    }

    KernelBaseGetGlobalData = (KernelBaseGetGlobalData_)GetProcAddress(KernelBase, "KernelBaseGetGlobalData");
    BaseFormatObjectAttributes = (BaseFormatObjectAttributes_)GetProcAddress(KernelBase, "BaseFormatObjectAttributes");
    GetPackageFullNameFromToken_ = (GetPackageFullNameFromToken__)GetProcAddress(KernelBase, "GetPackageFullNameFromToken");

    BaseSetLastNTError = (BaseSetLastNTError_)GetProcAddress(Kernel32, "BaseSetLastNTError");
    BasepAppXExtension = (BasepAppXExtension_)GetProcAddress(Kernel32, "BasepAppXExtension");
    BasepGetPackagedAppInfoForFile = (BasepGetPackagedAppInfoForFile_)GetProcAddress(Kernel32, "BasepGetPackagedAppInfoForFile");
    BasepReleasePackagedAppInfo = (BasepReleasePackagedAppInfo_)GetProcAddress(Kernel32, "BasepReleasePackagedAppInfo");

    BasepConstructSxsCreateProcessMessage = (BasepConstructSxsCreateProcessMessage_)GetProcAddress(Kernel32, "BasepConstructSxsCreateProcessMessage");
    BasepAppContainerEnvironmentExtension = (BasepAppContainerEnvironmentExtension_)GetProcAddress(Kernel32, "BasepAppContainerEnvironmentExtension");
    BasepFreeAppCompatData = (BasepFreeAppCompatData_)GetProcAddress(Kernel32, "BasepFreeAppCompatData");
    BasepReleaseAppXContext = (BasepReleaseAppXContext_)GetProcAddress(Kernel32, "BasepReleaseAppXContext");
    BasepReleaseSxsCreateProcessUtilityStruct = (BasepReleaseSxsCreateProcessUtilityStruct_)GetProcAddress(Kernel32, "BasepReleaseSxsCreateProcessUtilityStruct");
    BasepCheckWebBladeHashes = (BasepCheckWebBladeHashes_)GetProcAddress(Kernel32, "BasepCheckWebBladeHashes");
    BasepIsProcessAllowed = (BasepIsProcessAllowed_)GetProcAddress(Kernel32, "BasepIsProcessAllowed");
    BaseUpdateVDMEntry = (BaseUpdateVDMEntry_)GetProcAddress(Kernel32, "BaseUpdateVDMEntry");
    BasepProcessInvalidImage = (BasepProcessInvalidImage_)GetProcAddress(Kernel32, "BasepProcessInvalidImage");
    RaiseInvalid16BitExeError = (RaiseInvalid16BitExeError_)GetProcAddress(Kernel32, "RaiseInvalid16BitExeError");
    BaseIsDosApplication = (BaseIsDosApplication_)GetProcAddress(Kernel32, "BaseIsDosApplication");
    BasepCheckWinSaferRestrictions = (BasepCheckWinSaferRestrictions_)GetProcAddress(Kernel32, "BasepCheckWinSaferRestrictions");
    BasepQueryAppCompat = (BasepQueryAppCompat_)GetProcAddress(Kernel32, "BasepQueryAppCompat");
    BasepGetAppCompatData = (BasepGetAppCompatData_)GetProcAddress(Kernel32, "BasepGetAppCompatData");
    BasepInitAppCompatData = (BasepInitAppCompatData_)GetProcAddress(Kernel32, "BasepInitAppCompatData");
    BaseWriteErrorElevationRequiredEvent = (BaseWriteErrorElevationRequiredEvent_)GetProcAddress(Kernel32, "BaseWriteErrorElevationRequiredEvent");
    BaseCheckElevation = (BaseCheckElevation_)GetProcAddress(Kernel32, "BaseCheckElevation");
    BasepGetPackageActivationTokenForSxS = (BasepGetPackageActivationTokenForSxS_)GetProcAddress(Kernel32, "BasepGetPackageActivationTokenForSxS");

    BasepGetPackageActivationTokenForSxS2 = (BasepGetPackageActivationTokenForSxS2_)GetProcAddress(Kernel32, "BasepGetPackageActivationTokenForSxS2");

    BaseElevationPostProcessing = (BaseElevationPostProcessing_)GetProcAddress(Kernel32, "BaseElevationPostProcessing");
    BasepPostSuccessAppXExtension = (BasepPostSuccessAppXExtension_)GetProcAddress(Kernel32, "BasepPostSuccessAppXExtension");
    BasepFinishPackageActivationForSxS = (BasepFinishPackageActivationForSxS_)GetProcAddress(Kernel32, "BasepFinishPackageActivationForSxS");
    BaseDestroyVDMEnvironment = (BaseDestroyVDMEnvironment_)GetProcAddress(Kernel32, "BaseDestroyVDMEnvironment");


    IsBasepConstructSxsCreateProcessMessagePresent = IsBasepProcessInvalidImagePresent;
    IsBasepInitAppCompatDataPresent = IsBasepProcessInvalidImagePresent;
    IsBasepAppXExtensionPresent = IsBasepProcessInvalidImagePresent;
    IsBasepGetAppCompatDataPresent = IsBasepProcessInvalidImagePresent;
    IsBasepCheckWebBladeHashesPresent = IsBasepProcessInvalidImagePresent;
    IsBasepQueryModuleChpeSettingsPresent = IsBasepProcessInvalidImagePresent;
    IsBasepIsProcessAllowedPresent = IsBasepProcessInvalidImagePresent;
    IsBasepQueryAppCompatPresent = IsBasepProcessInvalidImagePresent;
    IsBasepAppContainerEnvironmentExtensionPresent = IsBasepProcessInvalidImagePresent;
    IsBasepCheckWinSaferRestrictionsPresent = IsBasepProcessInvalidImagePresent;
    IsBasepFreeAppCompatDataPresent = IsBasepProcessInvalidImagePresent;
    IsBasepReleaseSxsCreateProcessUtilityStructPresent = IsBasepProcessInvalidImagePresent;
    IsBaseCheckElevationPresent = IsBasepProcessInvalidImagePresent;
    IsBaseWriteErrorElevationRequiredEventPresent = IsBasepProcessInvalidImagePresent;
    IsBaseElevationPostProcessingPresent = IsBasepProcessInvalidImagePresent;
    IsBaseDestroyVDMEnvironmentPresent = IsBasepProcessInvalidImagePresent;
    IsBaseUpdateVDMEntryPresent = IsBasepProcessInvalidImagePresent;
    IsBaseIsDosApplicationPresent = IsBasepProcessInvalidImagePresent;
    IsNtVdm64CreateProcessInternalWPresent = IsBasepProcessInvalidImagePresent;
    IsRaiseInvalid16BitExeErrorPresent = IsBasepProcessInvalidImagePresent;

    RtlSetLastWin32Error(0);
}