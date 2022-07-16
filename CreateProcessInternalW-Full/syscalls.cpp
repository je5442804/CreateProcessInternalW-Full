#include "syscalls.hpp"
#include "structs.hpp"
#include <stdio.h>

#define JUMPER

SW3_SYSCALL_LIST SW3_SyscallList;

PVOID BaseStaticServerData;
ULONG KernelBaseGlobalData;
USHORT OSBuildNumber;

BasepIsRealtimeAllowed_ BasepIsRealtimeAllowed;
BasepAdjustApplicationPath_ BasepAdjustApplicationPath;
AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

IsPresentFunction IsBasepProcessInvalidImagePresent;
IsPresentFunction IsCheckAppXPackageBreakawayPresent;
IsPresentFunction IsGetAppExecutionAliasPathPresent;
IsPresentFunction IsLoadAppExecutionAliasInfoExPresent;

BasepConvertWin32AttributeList_ BasepConvertWin32AttributeList;
BasepFreeBnoIsolationParameter_ BasepFreeBnoIsolationParameter;
BasepAddToOrUpdateAttributesList_ BasepAddToOrUpdateAttributesList;
BasepCreateBnoIsolationObjectDirectories_ BasepCreateBnoIsolationObjectDirectories;
BasepCreateLowBox_ BasepCreateLowBox;
BasepCreateProcessParameters_ BasepCreateProcessParameters;
BuildSubSysCommandLine_ BuildSubSysCommandLine;
BasepGetConsoleHost_ BasepGetConsoleHost;
BasepUpdateProcessParametersField_ BasepUpdateProcessParametersField;
ValidateAppXAliasFallback_ ValidateAppXAliasFallback;
LoadAppExecutionAliasInfoForExecutable_ LoadAppExecutionAliasInfoForExecutable;

PVOID Ntdll;
PVOID Kernel32;
PVOID KernelBase;

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

PVOID SC(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
    if (OSBuildNumber !=0 && OSBuildNumber < 10586) //Beta 10525
    {
        distance_to_syscall = 0x08;
    }
    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
        return SyscallAddress;
    }
    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate
    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
            return SyscallAddress;
        }
    }
    return NULL;
}

int GetGloablVariable(PVOID Ntdll, DWORD SizeOfNtdll,PVOID Kernel32, DWORD SizeofKernel32, PVOID KernelBase, DWORD SizeofKernelBase)
{
    
    PVOID tempaddress = 0;
    PVOID BaseStaticServerDataAddress = 0;
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
    BaseStaticServerData =(char*)NtCurrentPeb()->ReadOnlySharedMemoryBase 
                        + (ULONGLONG)NtCurrentPeb()->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX]
                        - NtCurrentPeb()->CsrServerReadOnlySharedMemoryBase;
    if(BaseStaticServerData)
        dprintf(L"[+] BaseStaticServerData: 0x%p\n", BaseStaticServerData);
  
    //KernelBaseGlobalData
    return 0;
}

void GetUnexportFunction(PVOID KernelBase, DWORD SizeofKernelBase)
{
    BYTE signaturecode0[] = { 0x48,0x83,0xEC,0x20,0x45,0x33,0xC0,0xC7,0x40,0x10,0x0E,0x00,0x00,0x00 };//BasepIsRealtimeAllowed
    BYTE signaturecode1[] = { 0x0F,0xB7,0x11,0x4C,0x8B,0xC1,0xD1,0xEA};//BasepAdjustApplicationPath              0x75 0x07, 0xeb, 0x0a 
    BYTE signaturecode2[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x08,0x48,0x89,0x68,0x10,0x48,0x89,0x70,0x18 ,0x48,0x83,0xec,0x40,0x48,0x8b,0x5c,0x24,0x70};
    BYTE signaturecode3[] = { 0x48,0x83,0xec,0x28,0x8b,0x0d,  0x00,0x83,0xf9,0x01,0x75,0x04,0x8a,0xc1,0xeb,0x36,0x83,0xf9,0x02 };
    BYTE signaturecode4[] = { 0x48,0x89,0x5C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0x70,0xFF,0xFF,0xFF };//ValidateAppXAliasFallback
    BYTE signaturecode5[] = { 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x58, 0x4C, 0x8B, 0x8D };//BasepConvertWin32AttributeList
    BYTE signaturecode6[] = { 0XCC,0xCC,0x48,0x85,0xC9,0x74,0x38,0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57}; //BasepFreeBnoIsolationParameter
    BYTE signaturecode7[] = { 0xCC,0x48,0x89,0x5C,0x24,0x08,0x45,0x8B,0x19,0x85,0xD2,0x74,0x5B,0x4C,0x8D,0x51,0x08,0x8B,0xD2 };//BasepAddToOrUpdateAttributesList
    BYTE signaturecode8[] = { 0xCC,0x48,0x89,0x5C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x56,0x48,0x8B,0xEC,0x48,0x83,0xEC,0x70 };//BasepCreateBnoIsolationObjectDirectories
    BYTE signaturecode9[] = { 0x48,0x8D,0xAC,0x24,0x78,0xFC,0xFF,0xFF };//BasepCreateProcessParameters
    BYTE signaturecode10[] = { 0xC7,0x45,0xD0,0x08,0x00,0x0A,0x00 }; //BuildSubSysCommandLine
    BYTE signaturecode11[] = { 0x41,0xb9,0x08,0x00,0x00,0x00,0x48,0x83,0xc9,0xff }; //BasepGetConsoleHost
    BYTE signaturecode12[] = { 0x48,0x8b,0xf1,0x49,0x83,0xf8,0x04 };//BasepUpdateProcessParametersField
    BYTE signaturecode13[] = { 0x66,0x83,0xF8,0x7A };//LoadAppExecutionAliasInfoForExecutable

    int count2 = 0;
    PVOID TempAddress2[3] = { 0 };
    PVOID CreateAppContainerToken = (PVOID)GetProcAddress((HMODULE)KernelBase, "CreateAppContainerToken");
    BasepCreateLowBox = (BasepCreateLowBox_)((char*)CreateAppContainerToken + 9 + *(DWORD*)((char*)CreateAppContainerToken + 5));
    dprintf(L"[+] Got Unexported BasepCreateLowBox: 0x%p\n", BasepCreateLowBox);
    for (int i = 0; i < SizeofKernelBase - 0x100; i++ )
    {
        if (!BasepIsRealtimeAllowed && !memcmp(signaturecode0, (char*)KernelBase + i, sizeof(signaturecode0)))
        {
            for (int j = 0x6; j <= 0x18; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 3))
                {
                    BasepIsRealtimeAllowed = (BasepIsRealtimeAllowed_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BasepIsRealtimeAllowed: 0x%p\n", BasepIsRealtimeAllowed);
                    break;
                }
            }
        }

        if (!BasepAdjustApplicationPath && !memcmp(signaturecode1, (char*)KernelBase + i,sizeof(signaturecode1)))
        {
            BasepAdjustApplicationPath = (BasepAdjustApplicationPath_)((char*)KernelBase + i);
            dprintf(L"[+] Got Unexported BasepAdjustApplicationPath: 0x%p\n", BasepAdjustApplicationPath);
        }
        if ( !AppModelPolicy_GetPolicy_Internal && !memcmp(signaturecode2, (char*)KernelBase + i, 15))
        {
            int Flags = 0;
            BYTE temp1[] = { 0x45,0x33,0xc0,0x33,0xd2 };
            BYTE temp2[] = { 0x44,0x8b,0xc0,0x3d,0x25,0x02,0x00,0xc0 };
            for (int j = 0; j <= 10; j++)
            {
                if (!memcmp((char*)signaturecode2 + 15, (char*)KernelBase + i + 15 + j, 9))
                {
                    Flags = 1;
                    break;
                }
            }
            for (int j = 0x30; j <= 0x48 && Flags==1; j++)
            {
                if (!memcmp(temp1, (char*)KernelBase + i + j, sizeof(temp1)))
                {
                    for (int k = 10; k <= 24; j++)
                    {
                        if (!memcmp(temp2, (char*)KernelBase + i + j + k, sizeof(temp2)))
                        {
                            Flags = 2;
                            AppModelPolicy_GetPolicy_Internal = (AppModelPolicy_GetPolicy_Internal_)((char*)KernelBase + i);
                            dprintf(L"[+] Got Unexported AppModelPolicy_GetPolicy_Internal: 0x%p\n", AppModelPolicy_GetPolicy_Internal);
                            break;
                        }                      
                    }
                    break;
                }
            }

        }
        if ( !memcmp(signaturecode3, (char*)KernelBase + i, 6) && !memcmp((char*)signaturecode3 + 6, (char*)KernelBase + i + 9, 13))
        {
            BYTE temp3[] = { 0x48,0x8D,0x54,0x24,0x30,0xC6,0x44,0x24,0x30,0x00,0x48,0x8D,0x0D};
            BYTE temp4[] = { 0x00,0xE8,0x6A,0xFF,0xFF,0xFF,0x85,0xC0,0x78 };
            for (int j = 0x16; j <= 0x24; j++)
            {//IsCheckAppXPackageBreakawayPresent: 0x00007FF97A5508A8
                if (!memcmp(temp3, (char*)KernelBase + i + j, sizeof(temp3)))
                {
                    PVOID ApiSetPresenceAddress = (char*)KernelBase + i + j + 17 + *(DWORD*)((char*)KernelBase + i + j + 13);
                    dprintf(L"ApiSetPresenceAddress = 0x%p -- Function = 0x%p\n", ApiSetPresenceAddress, (char*)KernelBase + i);
                    if (!memcmp(ApiSetPresenceAddress, L"DF",6))
                    {
                        IsCheckAppXPackageBreakawayPresent = (IsPresentFunction)((char*)KernelBase + i);
                        dprintf(L"[+] [1] Got Unexported IsCheckAppXPackageBreakawayPresent: 0x%p\n", IsCheckAppXPackageBreakawayPresent);
                        break;
                    }
                    if (!memcmp(ApiSetPresenceAddress, L"XZ", 6))
                    {
                        TempAddress2[count2] = (char*)KernelBase + i;
                        count2++;
                        break;
                    }

                    if (!memcmp(ApiSetPresenceAddress, L"TV", 6))
                    {
                        IsBasepProcessInvalidImagePresent = (IsPresentFunction)((char*)KernelBase + i);
                        dprintf(L"[+] [3] Got Unexported IsBasepProcessInvalidImagePresent: 0x%p\n", IsBasepProcessInvalidImagePresent);
                        break;
                    }
                   
                }
            }
        }
        if (!ValidateAppXAliasFallback && !memcmp(signaturecode4, (char*)KernelBase + i, sizeof(signaturecode4)))
        {
            ValidateAppXAliasFallback = (ValidateAppXAliasFallback_)((char*)KernelBase + i);
            dprintf(L"[+] Got Unexported ValidateAppXAliasFallback: 0x%p\n", ValidateAppXAliasFallback);
        }
        if (!BasepConvertWin32AttributeList && !memcmp(signaturecode5, (char*)KernelBase + i, sizeof(signaturecode5)))
        {
            BYTE temp5[] = { 0xCC, 0xCC };
            for (int j = 4; j <= 0x20; j++)
            {
                if (!memcmp(temp5, (char*)KernelBase + i - j, sizeof(temp5)))
                {
                    BasepConvertWin32AttributeList = (BasepConvertWin32AttributeList_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BasepConvertWin32AttributeList: 0x%p\n", BasepConvertWin32AttributeList);
                    break;
                }
            }
        }
        if (!BasepFreeBnoIsolationParameter && !memcmp(signaturecode6, (char*)KernelBase + i, sizeof(signaturecode6)))
        {
            BasepFreeBnoIsolationParameter = (BasepFreeBnoIsolationParameter_)((char*)KernelBase + i + 2);
            dprintf(L"[+] Got Unexported BasepFreeBnoIsolationParameters: 0x%p\n", BasepFreeBnoIsolationParameter);
        }
        if (!BasepAddToOrUpdateAttributesList && !memcmp(signaturecode7, (char*)KernelBase + i, sizeof(signaturecode7)))
        {
            BasepAddToOrUpdateAttributesList = (BasepAddToOrUpdateAttributesList_)((char*)KernelBase + i + 1);
            dprintf(L"[+] Got Unexported BasepAddToOrUpdateAttributesList: 0x%p\n", BasepAddToOrUpdateAttributesList);
        }       
        if (!BasepCreateBnoIsolationObjectDirectories && !memcmp(signaturecode8, (char*)KernelBase + i, sizeof(signaturecode8)))
        {
            BasepCreateBnoIsolationObjectDirectories = (BasepCreateBnoIsolationObjectDirectories_)((char*)KernelBase + i + 1);
            dprintf(L"[+] Got Unexported BasepCreateBnoIsolationObjectDirectories: 0x%p\n", BasepCreateBnoIsolationObjectDirectories);
        }
        if (!BasepCreateProcessParameters && !memcmp(signaturecode9, (char*)KernelBase + i, sizeof(signaturecode9)))
        {
            for (int j = 0; j <= 0x18; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 2))
                {
                    BasepCreateProcessParameters = (BasepCreateProcessParameters_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BasepCreateProcessParameters: 0x%p\n", BasepCreateProcessParameters);
                    break;
                }
            }
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
        if (!BasepUpdateProcessParametersField && !memcmp(signaturecode12, (char*)KernelBase + i, sizeof(signaturecode12)))
        {
            for (int j = 0; j <= 0x24; j++)
            {
                if (!memcmp(signaturecode6, (char*)KernelBase + i - j, 2))
                {
                    BasepUpdateProcessParametersField = (BasepUpdateProcessParametersField_)((char*)KernelBase + i - j + 2);
                    dprintf(L"[+] Got Unexported BasepUpdateProcessParametersField: 0x%p\n", BasepUpdateProcessParametersField);
                    break;
                }
            }
        }
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
    }
   
    IsGetAppExecutionAliasPathPresent = (IsPresentFunction)TempAddress2[0];
    IsLoadAppExecutionAliasInfoExPresent = (IsPresentFunction)TempAddress2[1];
    dprintf(L"[*] IsGetAppExecutionAliasPathPresent: 0x%p\n", IsGetAppExecutionAliasPathPresent);
    dprintf(L"[*] IsLoadAppExecutionAliasInfoExPresent: 0x%p\n", IsLoadAppExecutionAliasInfoExPresent);

}
BOOL SW3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
    PVOID DllBase = NULL;
    //PVOID ntdll = 0;
    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    DWORD SizeOfNtdll = 0;
    //PVOID Kernel32 = 0;
    DWORD SizeofKernel32 = 0;
    //PVOID KernelBase = 0;
    DWORD SizeofKernelBase = 0;
    for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink; LdrEntry->DllBase != NULL; LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->InLoadOrderLinks.Flink)
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) == 'nrek')
        {
            if ((*(ULONG*)(DllName + 4) | 0x20202020) == '23le')
            {
                //wprintf(L"OK Kernel32: %p\n", DllBase);
                Kernel32 = DllBase;
                SizeofKernel32 = NtHeaders->OptionalHeader.SizeOfImage;
            }
            if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'able')
            {
                //wprintf(L"OK KernelBase: %p\n", DllBase);
                KernelBase = DllBase;
                SizeofKernelBase = NtHeaders->OptionalHeader.SizeOfImage;
            }
        }
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
        {
            //wprintf(L"OK Ntdll: %p\n", DllBase);
            Ntdll = DllBase;
            SizeOfNtdll = NtHeaders->OptionalHeader.SizeOfImage;
            ExportDirectoryNtdll = ExportDirectory;
        }
    }
    DllBase = 0;
    ExportDirectory = ExportDirectoryNtdll;
    if (!ExportDirectory)
        return FALSE;
    OSBuildNumber = Peb->OSBuildNumber;

    GetGloablVariable(Ntdll, SizeOfNtdll, Kernel32, SizeofKernel32, KernelBase, SizeofKernelBase);
    GetUnexportFunction(KernelBase, SizeofKernelBase);
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, Ntdll, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, Ntdll, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC(SW3_RVA2VA(PVOID, Ntdll, Entries[i].Address));

            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW3_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}
EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

    while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW3_SyscallList.Count;
    }
    return SW3_SyscallList.Entries[index].SyscallAddress;
}
