#include <stdio.h>
#include "otherapi.hpp"


void CreateInfoOutPut(PS_CREATE_INFO CreateInfo)
{
	/*
	wprintf(L"CreateInfo.InitFlags: 0x%08x\n", CreateInfo.InitState.u1.InitFlags);
	wprintf(L"CreateInfo.WriteOutputOnExit: 0x%08x\n", CreateInfo.InitState.u1.s1.WriteOutputOnExit);
	wprintf(L"CreateInfo.DetectManifest: 0x%08x\n", CreateInfo.InitState.u1.s1.DetectManifest);
	wprintf(L"CreateInfo.IFEOSkipDebugger: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEOSkipDebugger);
	wprintf(L"CreateInfo.IFEODoNotPropagateKeyState: 0x%08x\n", CreateInfo.InitState.u1.s1.IFEODoNotPropagateKeyState);
	wprintf(L"CreateInfo.SpareBits1: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits1);
	wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.InitState.u1.s1.SpareBits2);
	wprintf(L"CreateInfo.ProhibitedImageCharacteristics: 0x%08x\n", CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics);
	*/
	//wprintf(L"==================================================================\n");
	wprintf(L"CreateInfo.OutputFlags: 0x%08lx\n", CreateInfo.SuccessState.u2.OutputFlags);
	wprintf(L"CreateInfo.ProtectedProcess: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcess);
	wprintf(L"CreateInfo.ProtectedProcessLight: %d\n", CreateInfo.SuccessState.u2.s2.ProtectedProcessLight);
	wprintf(L"CreateInfo.AddressSpaceOverride: %d\n", CreateInfo.SuccessState.u2.s2.AddressSpaceOverride);
	wprintf(L"CreateInfo.DevOverrideEnabled: %d\n", CreateInfo.SuccessState.u2.s2.DevOverrideEnabled);
	wprintf(L"CreateInfo.ManifestDetected: %d\n", CreateInfo.SuccessState.u2.s2.ManifestDetected);
	//wprintf(L"CreateInfo.SpareBits1: 0x%03x\n", CreateInfo.SuccessState.u2.s2.SpareBits1);
	//wprintf(L"CreateInfo.SpareBits2: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits2);
	//wprintf(L"CreateInfo.SpareBits3: 0x%08x\n", CreateInfo.SuccessState.u2.s2.SpareBits3);
	wprintf(L"------------------------------------------------------------------\n");
	wprintf(L"CreateInfo.FileHandle:0x%p\n", CreateInfo.SuccessState.FileHandle);
	wprintf(L"CreateInfo.SectionHandle: 0x%p\n", CreateInfo.SuccessState.SectionHandle);
	wprintf(L"CreateInfo.UserProcessParametersNative: 0x%p\n", (PVOID)CreateInfo.SuccessState.UserProcessParametersNative);

	if (CreateInfo.SuccessState.UserProcessParametersWow64)
		wprintf(L"CreateInfo.UserProcessParametersWow64: 0x%p\n", UlongToPtr(CreateInfo.SuccessState.UserProcessParametersWow64));

	wprintf(L"CreateInfo.CurrentParameterFlags: 0x%08lx\n", CreateInfo.SuccessState.CurrentParameterFlags);
	wprintf(L"CreateInfo.PebAddressNative: 0x%p\n", (PVOID)CreateInfo.SuccessState.PebAddressNative);

	if (CreateInfo.SuccessState.PebAddressWow64)
		wprintf(L"CreateInfo.PebAddressWow64: 0x%p\n", UlongToPtr(CreateInfo.SuccessState.PebAddressWow64));

	wprintf(L"CreateInfo.ManifestAddress: 0x%p\n", (PVOID)CreateInfo.SuccessState.ManifestAddress);
	wprintf(L"CreateInfo.ManifestSize: %ld\n", CreateInfo.SuccessState.ManifestSize);
	//wprintf(L"------------------------------------------------------------------\n");
	wprintf(L"==================================================================\n");
}

void SectionImageInfomationOutPut(SECTION_IMAGE_INFORMATION SectionImageInfomation)
{
	wprintf(L"ImageInformation.Machine: 0x%hx\n", SectionImageInfomation.Machine);
	wprintf(L"ImageInformation.SubSystemType: %ld\n", SectionImageInfomation.SubSystemType);
	//(Major.Minor)
	wprintf(L"ImageInformation.SubSystemVersion: %hd.%hd\n", SectionImageInfomation.SubSystemMajorVersion, SectionImageInfomation.SubSystemMinorVersion);
	wprintf(L"ImageInformation.OperatingSystemVersion: %hd.%hd\n", SectionImageInfomation.MajorOperatingSystemVersion, SectionImageInfomation.MinorOperatingSystemVersion);

	wprintf(L"ImageInformation.ImageFileSize: %ld\n", SectionImageInfomation.ImageFileSize);
	wprintf(L"ImageInformation.TransferAddress: 0x%p\n", SectionImageInfomation.TransferAddress);
	//wprintf(L"ImageInformation.LoaderFlags: %ld\n", SectionImageInfomation.LoaderFlags);
	wprintf(L"ImageInformation.DllCharacteristics: 0x%04hX\n", SectionImageInfomation.DllCharacteristics);
	wprintf(L"============================================================================================\n");
}

void BaseCreateProcessMessageOutPut(BASE_SXS_CREATEPROCESS_MSG BaseCreateProcessMessageSxs)
{

	//wprintf(L"[*] BaseCreateProcessMessageSxs Pointer 0x%p\n", &BaseCreateProcessMessageSxs);
	wprintf(L"[*] Flags: 0x%08lx\n", BaseCreateProcessMessageSxs.Flags);
	wprintf(L"[*] ProcessParameterFlags.Flags: 0x%08lx\n", BaseCreateProcessMessageSxs.ProcessParameterFlags);

	if (BaseCreateProcessMessageSxs.AssemblyDirectory.Length)
		wprintf(L"[*] AssemblyDirectory: %ls, Length: %d,  MaximumLength: %d\n", BaseCreateProcessMessageSxs.AssemblyDirectory.Buffer, BaseCreateProcessMessageSxs.AssemblyDirectory.Length, BaseCreateProcessMessageSxs.AssemblyDirectory.MaximumLength);
	wprintf(L"[*] ActivationContextRunLevel.RunLevel: %d\n", BaseCreateProcessMessageSxs.ActivationContextRunLevel.RunLevel);
	wprintf(L"[*] CultureFallBacks: \"");
	for (USHORT i = 0; i < BaseCreateProcessMessageSxs.CultureFallBacks.Length / sizeof(WCHAR) - sizeof(UNICODE_NULL); i++) {
		if (BaseCreateProcessMessageSxs.CultureFallBacks.Buffer[i] == L'\0')
		{
			if (BaseCreateProcessMessageSxs.CultureFallBacks.Buffer[i + 1] == L'\0')
				break;
			else
				wprintf(L"\\0");
		}
		else
		{
			wprintf(L"%c", BaseCreateProcessMessageSxs.CultureFallBacks.Buffer[i]);
		}
		
	}
	wprintf(L"\" Length = %hd, MaximumLength = %hd\n", BaseCreateProcessMessageSxs.CultureFallBacks.Length, BaseCreateProcessMessageSxs.CultureFallBacks.MaximumLength);
	wprintf(L"[*] AssemblyName Length: %hd, MaximumLength: %hd\n", BaseCreateProcessMessageSxs.AssemblyName.Length, BaseCreateProcessMessageSxs.AssemblyName.MaximumLength);
	wprintf(L"[*] AssemblyName: %ls\n", BaseCreateProcessMessageSxs.AssemblyName.Buffer);
	wprintf(L"[*] SxsSupportOSVersion: %hd.%hd (SwitchBack Context)\n", BaseCreateProcessMessageSxs.SxsSupportOSInfo.MajorVersion, BaseCreateProcessMessageSxs.SxsSupportOSInfo.MinorVersion);
	wprintf(L"[*] SxsMaxVersionTested: ");
	for (int n = 3; n >= 0; n--)
	{
		wprintf(L"%hd", *(USHORT*)((char*)&BaseCreateProcessMessageSxs.SxsMaxVersionTested + sizeof(USHORT) * n));
		if (n > 0)
			wprintf(L".");
		else
			wprintf(L"\n");
	}
	if (*BaseCreateProcessMessageSxs.ApplicationUserModelId)
		wprintf(L"[*] Sxs.ApplicationUserModelId: %ls\n", BaseCreateProcessMessageSxs.ApplicationUserModelId);
}