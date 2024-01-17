#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

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
} SW3_SYSCALL_ENTRY, * PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
	DWORD Count;
	SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, * PSW3_SYSCALL_LIST;

DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList();

extern	PBASE_STATIC_SERVER_DATA BaseStaticServerData;
extern	ULONG KernelBaseGlobalData;
extern	USHORT OSBuildNumber;
extern	HANDLE ConhostConsoleHandle;

extern	AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

extern	ApiSetCheckFunction IsBasepConstructSxsCreateProcessMessagePresent;
extern	ApiSetCheckFunction IsBasepInitAppCompatDataPresent;
extern	ApiSetCheckFunction IsBasepAppXExtensionPresent;
extern	ApiSetCheckFunction IsBasepGetPackagedAppInfoForFilePresent;
extern	ApiSetCheckFunction IsBasepGetAppCompatDataPresent;
extern	ApiSetCheckFunction IsBaseCheckElevationPresent;
extern	ApiSetCheckFunction IsBaseWriteErrorElevationRequiredEventPresent;
extern	ApiSetCheckFunction IsBasepCheckWebBladeHashesPresent;
extern	ApiSetCheckFunction IsBasepQueryModuleChpeSettingsPresent;
extern	ApiSetCheckFunction IsBasepIsProcessAllowedPresent;
extern	ApiSetCheckFunction IsBasepQueryAppCompatPresent;
extern	ApiSetCheckFunction IsBasepAppContainerEnvironmentExtensionPresent;
extern	ApiSetCheckFunction IsBasepCheckWinSaferRestrictionsPresent;
extern	ApiSetCheckFunction IsBasepFreeAppCompatDataPresent;
extern	ApiSetCheckFunction IsBasepReleaseSxsCreateProcessUtilityStructPresent;
extern	ApiSetCheckFunction IsBasepProcessInvalidImagePresent;
extern	ApiSetCheckFunction IsBaseElevationPostProcessingPresent;
extern	ApiSetCheckFunction IsBaseDestroyVDMEnvironmentPresent;
extern	ApiSetCheckFunction IsBaseUpdateVDMEntryPresent;
extern	ApiSetCheckFunction IsBaseIsDosApplicationPresent;
extern	ApiSetCheckFunction IsNtVdm64CreateProcessInternalWPresent;
extern	ApiSetCheckFunction IsRaiseInvalid16BitExeErrorPresent;

extern	ApiSetCheckFunction IsCheckAppXPackageBreakawayPresent;
extern	ApiSetCheckFunction IsGetAppExecutionAliasPathPresent;
extern	ApiSetCheckFunction IsLoadAppExecutionAliasInfoExPresent;
extern	ApiSetCheckFunction IsGetAppExecutionAliasPathExPresent;

extern	BasepConvertWin32AttributeList_ BasepConvertWin32AttributeList_inline;
extern	BasepCreateLowBox_ BasepCreateLowBox;

extern	BuildSubSysCommandLine_ BuildSubSysCommandLine;
extern	BasepGetConsoleHost_ BasepGetConsoleHost;

//extern	LoadAppExecutionAliasInfoForExecutable_ LoadAppExecutionAliasInfoForExecutable;

extern	GetPackageFullNameFromToken__ GetPackageFullNameFromToken_;

extern	KernelBaseGetGlobalData_ KernelBaseGetGlobalData;
extern	BaseFormatObjectAttributes_ BaseFormatObjectAttributes;
extern	CheckAppXPackageBreakaway_ CheckAppXPackageBreakaway;
extern	LoadAppExecutionAliasInfoEx_ LoadAppExecutionAliasInfoEx;
extern	GetAppExecutionAliasPath_ GetAppExecutionAliasPath;
extern	GetAppExecutionAliasPathEx_ GetAppExecutionAliasPathEx;

extern	CompletePackagedProcessCreationEx_ CompletePackagedProcessCreationEx;
extern	CompleteAppExecutionAliasProcessCreationEx_ CompleteAppExecutionAliasProcessCreationEx;
extern	PerformAppxLicenseRundownEx_ PerformAppxLicenseRundownEx;
extern	FreeAppExecutionAliasInfoEx_ FreeAppExecutionAliasInfoEx;
extern	GetEmbeddedImageMitigationPolicy_ GetEmbeddedImageMitigationPolicy;
extern	BaseSetLastNTError_ BaseSetLastNTError;
extern	BasepAppXExtension_ BasepAppXExtension;
extern	BasepGetPackagedAppInfoForFile_ BasepGetPackagedAppInfoForFile;
extern	BasepConstructSxsCreateProcessMessage_ BasepConstructSxsCreateProcessMessage;
extern	BasepAppContainerEnvironmentExtension_ BasepAppContainerEnvironmentExtension;
extern	BasepFreeAppCompatData_ BasepFreeAppCompatData;
extern	BasepReleaseAppXContext_ BasepReleaseAppXContext;
extern	BasepReleaseSxsCreateProcessUtilityStruct_ BasepReleaseSxsCreateProcessUtilityStruct;
extern	BasepCheckWebBladeHashes_ BasepCheckWebBladeHashes;
extern	BasepIsProcessAllowed_ BasepIsProcessAllowed;
extern	BaseUpdateVDMEntry_ BaseUpdateVDMEntry;
extern	BasepProcessInvalidImage_ BasepProcessInvalidImage;
extern	RaiseInvalid16BitExeError_ RaiseInvalid16BitExeError;
extern	BaseIsDosApplication_ BaseIsDosApplication;
extern	BasepCheckWinSaferRestrictions_ BasepCheckWinSaferRestrictions;
extern	BasepQueryAppCompat_ BasepQueryAppCompat;
extern	BasepGetAppCompatData_ BasepGetAppCompatData;
extern	BasepInitAppCompatData_ BasepInitAppCompatData;
extern	BaseWriteErrorElevationRequiredEvent_ BaseWriteErrorElevationRequiredEvent;
extern	BaseCheckElevation_ BaseCheckElevation;
extern	BasepGetPackageActivationTokenForSxS_ BasepGetPackageActivationTokenForSxS;
extern	BasepGetPackageActivationTokenForSxS2_ BasepGetPackageActivationTokenForSxS2;
extern	BaseElevationPostProcessing_ BaseElevationPostProcessing;
extern	BasepPostSuccessAppXExtension_ BasepPostSuccessAppXExtension;
extern	BasepFinishPackageActivationForSxS_ BasepFinishPackageActivationForSxS;
extern	BasepReleasePackagedAppInfo_ BasepReleasePackagedAppInfo;
extern	BaseDestroyVDMEnvironment_ BaseDestroyVDMEnvironment;

extern	NtVdm64CreateProcessInternalW_ NtVdm64CreateProcessInternalW;

extern	HMODULE Ntdll;
extern	HMODULE Kernel32;
extern	HMODULE KernelBase;
extern	USHORT NtdllRevision;
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);
void init();
void init2();
#endif
