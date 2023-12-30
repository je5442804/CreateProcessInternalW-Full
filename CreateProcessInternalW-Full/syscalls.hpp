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

extern	PVOID BaseStaticServerData;
extern	ULONG KernelBaseGlobalData;
extern	USHORT OSBuildNumber;

extern	BasepIsRealtimeAllowed_ BasepIsRealtimeAllowed;
extern	BasepAdjustApplicationPath_ BasepAdjustApplicationPath;
extern	AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

extern	ApiSetCheckFunction IsBasepConstructSxsCreateProcessMessagePresent;
extern	ApiSetCheckFunction IsBasepInitAppCompatDataPresent;
extern	ApiSetCheckFunction IsBasepAppXExtensionPresent;
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

extern	ValidateAppXAliasFallback_ ValidateAppXAliasFallback;
extern	BasepConvertWin32AttributeList_ BasepConvertWin32AttributeList_inline;
extern	BasepFreeBnoIsolationParameter_ BasepFreeBnoIsolationParameter;
extern	BasepAddToOrUpdateAttributesList_ BasepAddToOrUpdateAttributesList;
extern	BasepCreateBnoIsolationObjectDirectories_ BasepCreateBnoIsolationObjectDirectories;
extern	BasepCreateLowBox_ BasepCreateLowBox;
extern	BasepCreateProcessParameters_ BasepCreateProcessParameters;
extern	BuildSubSysCommandLine_ BuildSubSysCommandLine;
extern	BasepGetConsoleHost_ BasepGetConsoleHost;
extern	BasepUpdateProcessParametersField_ BasepUpdateProcessParametersField;
extern	LoadAppExecutionAliasInfoForExecutable_ LoadAppExecutionAliasInfoForExecutable;

extern	CsrCaptureMessageMultiUnicodeStringsInPlace_ CsrCaptureMessageMultiUnicodeStringsInPlace;
extern	CsrClientCallServer_ CsrClientCallServer;
extern	DbgUiConnectToDbg_ DbgUiConnectToDbg;
extern	DbgUiGetThreadDebugObject_ DbgUiGetThreadDebugObject;
extern	RtlSetLastWin32Error_ RtlSetLastWin32Error;
extern	RtlGetExePath_ RtlGetExePath;
extern	RtlReleasePath_ RtlReleasePath;
extern	RtlInitUnicodeString_ RtlInitUnicodeString;
extern	RtlInitUnicodeStringEx_ RtlInitUnicodeStringEx;
extern	RtlFreeUnicodeString_ RtlFreeUnicodeString;
extern	RtlDosPathNameToNtPathName_U_ RtlDosPathNameToNtPathName_U;
extern	RtlDetermineDosPathNameType_U_ RtlDetermineDosPathNameType_U;
extern	RtlGetFullPathName_UstrEx_ RtlGetFullPathName_UstrEx;
extern	RtlIsDosDeviceName_U_ RtlIsDosDeviceName_U;
extern	RtlAllocateHeap_ RtlAllocateHeap;
extern	RtlFreeHeap_ RtlFreeHeap;
extern	RtlCreateEnvironmentEx_ RtlCreateEnvironmentEx;
extern	RtlImageNtHeader_ RtlImageNtHeader;
extern	RtlDestroyEnvironment_ RtlDestroyEnvironment;
extern	RtlWow64GetProcessMachines_ RtlWow64GetProcessMachines;
extern	RtlDestroyProcessParameters_ RtlDestroyProcessParameters;
extern	LdrQueryImageFileKeyOption_ LdrQueryImageFileKeyOption;
extern	RtlGetVersion_ RtlGetVersion;
extern	GetPackageFullNameFromToken__ GetPackageFullNameFromToken_;
extern	CsrFreeCaptureBuffer_ CsrFreeCaptureBuffer;
extern	KernelBaseGetGlobalData_ KernelBaseGetGlobalData;
extern	BaseFormatObjectAttributes_ BaseFormatObjectAttributes;
extern	CheckAppXPackageBreakaway_ CheckAppXPackageBreakaway;
extern	LoadAppExecutionAliasInfoEx_ LoadAppExecutionAliasInfoEx;
extern	GetAppExecutionAliasPath_ GetAppExecutionAliasPath;
extern	CompleteAppExecutionAliasProcessCreationEx_ CompleteAppExecutionAliasProcessCreationEx;
extern	PerformAppxLicenseRundownEx_ PerformAppxLicenseRundownEx;
extern	FreeAppExecutionAliasInfoEx_ FreeAppExecutionAliasInfoEx;
extern	GetEmbeddedImageMitigationPolicy_ GetEmbeddedImageMitigationPolicy;
extern	BaseSetLastNTError_ BaseSetLastNTError;
extern	BasepAppXExtension_ BasepAppXExtension;
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
extern	BaseElevationPostProcessing_ BaseElevationPostProcessing;
extern	BasepPostSuccessAppXExtension_ BasepPostSuccessAppXExtension;
extern	BasepFinishPackageActivationForSxS_ BasepFinishPackageActivationForSxS;
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
#endif
