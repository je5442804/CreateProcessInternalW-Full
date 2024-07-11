﻿#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#pragma once
#ifndef SYSCALL_HEADER_H_
#define SYSCALL_HEADER_H_

#include <windows.h>
#include <iostream>
#include "otherapi.hpp"

#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

extern	PBASE_STATIC_SERVER_DATA BaseStaticServerData;
extern	ULONG KernelBaseGlobalData;
extern	USHORT OSBuildNumber;
extern	HANDLE ConhostConsoleHandle;

extern	AppModelPolicy_GetPolicy_Internal_ AppModelPolicy_GetPolicy_Internal;

extern	ApiSetCheckFunction IsBasepConstructSxsCreateProcessMessagePresent;
extern	ApiSetCheckFunction IsBasepInitAppCompatDataPresent;
extern	ApiSetCheckFunction IsBasepAppXExtensionPresent;
extern  ApiSetCheckFunction IsBasepCheckPplSupportPresent;
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
extern	USHORT NtdllBuildNumber;

void init();
void init2();
#endif