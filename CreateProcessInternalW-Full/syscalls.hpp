#pragma once

#ifndef SW3_HEADER_H_
#define SW3_HEADER_H_

#include <windows.h>
#include <iostream>
#include "otherapi.hpp"

#define SW3_SEED 0x61EA92A9
#define SW3_ROL8(v) (v << 8 | v >> 24)
#define SW3_ROR8(v) (v >> 8 | v << 24)
#define SW3_ROX8(v) ((SW3_SEED % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 500
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _SW3_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
	PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, *PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
    DWORD Count;
    SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, *PSW3_SYSCALL_LIST;

DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList();

extern PVOID BaseStaticServerData;
extern ULONG KernelBaseGlobalData;
extern USHORT OSBuildNumber;

extern BasepIsRealtimeAllowed_ BasepIsRealtimeAllowed;
extern BasepAdjustApplicationPath_ BasepAdjustApplicationPath;
extern AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

extern IsPresentFunction IsBasepProcessInvalidImagePresent;
extern IsPresentFunction IsCheckAppXPackageBreakawayPresent;
extern IsPresentFunction IsGetAppExecutionAliasPathPresent;
extern IsPresentFunction IsLoadAppExecutionAliasInfoExPresent;

extern ValidateAppXAliasFallback_ ValidateAppXAliasFallback;
extern BasepConvertWin32AttributeList_ BasepConvertWin32AttributeList;
extern BasepFreeBnoIsolationParameter_ BasepFreeBnoIsolationParameter;
extern BasepAddToOrUpdateAttributesList_ BasepAddToOrUpdateAttributesList;
extern BasepCreateBnoIsolationObjectDirectories_ BasepCreateBnoIsolationObjectDirectories;
extern BasepCreateLowBox_ BasepCreateLowBox;
extern BasepCreateProcessParameters_ BasepCreateProcessParameters;
extern BuildSubSysCommandLine_ BuildSubSysCommandLine;
extern BasepGetConsoleHost_ BasepGetConsoleHost;
extern BasepUpdateProcessParametersField_ BasepUpdateProcessParametersField;
extern LoadAppExecutionAliasInfoForExecutable_ LoadAppExecutionAliasInfoForExecutable;

extern PVOID Ntdll;
extern PVOID Kernel32;
extern PVOID KernelBase;

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);

#endif
