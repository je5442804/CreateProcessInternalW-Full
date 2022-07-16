#include "otherapi.hpp"
#include <stdio.h>

void CreateInfoOutPut(PS_CREATE_INFO CreateInfo)
{
	wprintf(L"CreateInfo.InitFlags: 0x%08x\n", CreateInfo.InitState.u1.InitFlags);
	wprintf(L"CreateInfo.WriteOutputOnExit: 0x%08x\n", CreateInfo.InitState.u1.s1.WriteOutputOnExit);
	wprintf(L"CreateInfo.DetectManifest: 0x%08x\n", CreateInfo.InitState.u1.s1.DetectManifest);
	wprintf(L"CreateInfo.IFEOSkipDebugger: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEOSkipDebugger);
	wprintf(L"CreateInfo.IFEODoNotPropagateKeyState: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEODoNotPropagateKeyState);
	wprintf(L"CreateInfo.SpareBits1: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits1);
	wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits2);
	wprintf(L"CreateInfo.ProhibitedImageCharacteristics: 0x%08x\n", CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics);
	wprintf(L"============================================================================================\n");
	wprintf(L"CreateInfo.OutputFlags: %d\n", CreateInfo.SuccessState.u2.OutputFlags);
	wprintf(L"CreateInfo.ProtectedProcess: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcess);
	wprintf(L"CreateInfo.ProtectedProcessLight: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcessLight);
	wprintf(L"CreateInfo.AddressSpaceOverride: %d\n", CreateInfo.SuccessState.u2.s2.AddressSpaceOverride);
	wprintf(L"CreateInfo.DevOverrideEnabled: %d\n", CreateInfo.SuccessState.u2.s2.DevOverrideEnabled);
	wprintf(L"CreateInfo.ManifestDetected: %d\n", CreateInfo.SuccessState.u2.s2.ManifestDetected);
	wprintf(L"CreateInfo.SpareBits1: 0x%03x\n", CreateInfo.SuccessState.u2.s2.SpareBits1);
	wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits2);
	wprintf(L"CreateInfo.SpareBits3: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits3);
	wprintf(L"--------------------------------------------------------------------------------------------\n");
	wprintf(L"CreateInfo.FileHandle:0x%p\n", CreateInfo.SuccessState.FileHandle);
	wprintf(L"CreateInfo.SectionHandle: 0x%p\n", CreateInfo.SuccessState.SectionHandle);
	wprintf(L"CreateInfo.UserProcessParametersNative: 0x%p\n", (PVOID)CreateInfo.SuccessState.UserProcessParametersNative);
	wprintf(L"CreateInfo.CurrentParameterFlags: 0x%08lx\n", CreateInfo.SuccessState.CurrentParameterFlags);
	wprintf(L"CreateInfo.PebAddressNative: 0x%p\n",(PVOID)CreateInfo.SuccessState.PebAddressNative);
	wprintf(L"CreateInfo.ManifestAddress: 0x%p\n", (PVOID)CreateInfo.SuccessState.ManifestAddress);
	wprintf(L"CreateInfo.ManifestSize: %d\n", CreateInfo.SuccessState.ManifestSize);
	wprintf(L"--------------------------------------------------------------------------------------------\n");
	wprintf(L"CreateInfo.ExeFormat.DllCharacteristics: 0x%08x\n", CreateInfo.ExeFormat.DllCharacteristics);
	wprintf(L"============================================================================================\n");
}
void SectionImageInfomationOutPut(SECTION_IMAGE_INFORMATION SectionImageInfomation)
{
	wprintf(L"ImageInformation.Machine: %d\n", SectionImageInfomation.Machine);
	wprintf(L"ImageInformation.SubSystemType: %d\n", SectionImageInfomation.SubSystemType);
	wprintf(L"ImageInformation.SubSystemMinorVersion: %d\n", SectionImageInfomation.SubSystemMinorVersion);
	wprintf(L"ImageInformation.SubSystemMajorVersion: %d\n", SectionImageInfomation.SubSystemMajorVersion);
	wprintf(L"ImageInformation.SubSystemVersion: %d\n", SectionImageInfomation.SubSystemVersion);
	wprintf(L"ImageInformation.MajorOperatingSystemVersion: %d\n", SectionImageInfomation.MajorOperatingSystemVersion);
	wprintf(L"ImageInformation.MinorOperatingSystemVersion: %d\n", SectionImageInfomation.MinorOperatingSystemVersion);
	wprintf(L"ImageInformation.OperatingSystemVersion: %d\n", SectionImageInfomation.OperatingSystemVersion);
	wprintf(L"ImageInformation.ImageFileSize: %d\n", SectionImageInfomation.ImageFileSize);
	wprintf(L"ImageInformation.TransferAddress: 0x%p\n", SectionImageInfomation.TransferAddress);
	wprintf(L"ImageInformation.LoaderFlags: %d\n", SectionImageInfomation.LoaderFlags);
	wprintf(L"ImageInformation.DllCharacteristics: 0x%08x\n", SectionImageInfomation.DllCharacteristics);
	wprintf(L"============================================================================================\n");
}
void BaseCreateProcessMessageOutPut(BASE_SXS_CREATEPROCESS_MSG BaseCreateProcessMessageSxs)
{
	//wprintf(L"[*] BaseCreateProcessMessageSxs Pointer 0x%p\n", &BaseCreateProcessMessageSxs);
	wprintf(L"[*] Flags: 0x%08lx\n", BaseCreateProcessMessageSxs.Flags);
	wprintf(L"[*] ProcessParameterFlags.Flags: 0x%08lx\n", BaseCreateProcessMessageSxs.ProcessParameterFlags);
	wprintf(L"[*] AssemblyDirectory: %ls === MaximumLength: %d\n", BaseCreateProcessMessageSxs.AssemblyDirectory.Buffer, BaseCreateProcessMessageSxs.AssemblyDirectory.MaximumLength);
	wprintf(L"[*] ActivationContextRunLevel.RunLevel: %d\n", BaseCreateProcessMessageSxs.ActivationContextRunLevel.RunLevel);
	wprintf(L"[*] CacheSxsLanguageBuffers: %ls, Length = %d\n", BaseCreateProcessMessageSxs.CacheSxsLanguageBuffer.Buffer, BaseCreateProcessMessageSxs.CacheSxsLanguageBuffer.Length);
	wprintf(L"[*] AssemblyIdentity Length: %d\n", BaseCreateProcessMessageSxs.AssemblyIdentity.Length);
	wprintf(L"[*] AssemblyIdentity: %ls\n", BaseCreateProcessMessageSxs.AssemblyIdentity.Buffer);
	wprintf(L"[*] SxsProcessorArchitecture[uncorrected]: %d\n", BaseCreateProcessMessageSxs.SxsProcessorArchitecture);
	wprintf(L"[*] SxsMaxVersionTested: ");
	for (int n = 3; n >= 0; n--)
	{
		wprintf(L"%d", *(USHORT*)((char*)&BaseCreateProcessMessageSxs.SxsMaxVersionTested + sizeof(USHORT) * n));
		if (n > 0)
			wprintf(L".");
		else
			wprintf(L"\n");
	}
	if(*BaseCreateProcessMessageSxs.ApplicationUserModelId)
		wprintf(L"[*] Sxs.ApplicationUserModelId: %ls\n", BaseCreateProcessMessageSxs.ApplicationUserModelId);
}
