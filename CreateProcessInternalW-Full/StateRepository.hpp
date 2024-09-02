//
// do not aaaaaa
//

/*
namespace StateRepository
{

	enum RuntimeBehavior
	{
		RuntimeBehavior_Unknow,
		RuntimeBehavior_Universal,
		RuntimeBehavior_DesktopBridge,
		RuntimeBehavior_Win32alacarte,
		RuntimeBehavior_AppSilo
	};
	enum AppLifecycleBehavior
	{
		Unknow,
		Unmanaged,
		SystemManaged
	};
	enum  SRTrustLevel
	{
		SRTrustLevel_Unknown,
		SRTrustLevel_PartialTrust,
		SRTrustLevel_FullTrust
	};
	enum BnoIsolation
	{
		None,
		Package
	};
}
enum StateRepository::Cache::Entity::PackageFamily_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_PackageFamilyName = 0x0001,
	Field_PackageSID = 0x0002,
	Field_Publisher = 0x0004,
};
enum StateRepository::Cache::PackageIntegrity : int {
	Unknown = 0x0000,
	Default = 0x0001,
	On = 0x0002,
	Off = 0x0003,
};
enum StateRepository::Cache::Entity::PackageMachineStatus_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_PackageIdentity = 0x0001,
	Field_PackageFullName = 0x0002,
	Field_Status = 0x0004,
};


enum StateRepository::Cache::Entity::ApplicationExtension_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_Application = 0x0001,
	Field_Index = 0x0002,
	Field_Flags = 0x0004,
	Field_Category = 0x0008,
	Field_Activation = 0x0010,
	Field_HostId = 0x0020,
	Field_Parameters = 0x0040,
	Field_CurrentDirectoryPath = 0x0080,
	Field__Dictionary = 0x0100,
};
enum StateRepository::Cache::Entity::AppExtension_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_Name = 0x0001,
	Field_Id = 0x0002,
	Field_PublicFolder = 0x0004,
	Field_DisplayName = 0x0008,
	Field_Description = 0x0010,
	Field_Extension = 0x0020,
	Field__Dictionary = 0x0040,
};
enum StateRepository::Cache::Entity::Activation_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_ActivationKey = 0x0001,
	Field_Flags = 0x0002,
	Field_HostId = 0x0004,
	Field_Executable = 0x0008,
	Field_Entrypoint = 0x0010,
	Field_RuntimeType = 0x0020,
	Field_StartPage = 0x0040,
	Field_ResourceGroup = 0x0080,
};
enum StateRepository::Cache::Entity::Application_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_Package = 0x0001,
	Field_Index = 0x0002,
	Field_Flags = 0x0004,
	Field_PackageRelativeApplicationId = 0x0008,
	Field_ApplicationUserModelId = 0x0010,
	Field_Activation = 0x0020,
	Field_HostId = 0x0040,
	Field_Parameters = 0x0080,
	Field_CurrentDirectoryPath = 0x0100,
	Field_Executable = 0x0200,
	Field_Entrypoint = 0x0400,
	Field_StartPage = 0x0800,
};
enum StateRepository::Cache::Entity::ApplicationUser_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_User = 0x0001,
	Field_ApplicationIdentity = 0x0002,
	Field_Application = 0x0004,
	Field_PackageUser = 0x0008,
	Field_ApplicationUserModelId = 0x0010,
};
enum StateRepository::Cache::Entity::DynamicAppUriHandlerGroup_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_User = 0x0001,
	Field_PackageFamily = 0x0002,
	Field_Name = 0x0004,
};
enum StateRepository::Cache::PackageType : int {
	Unknown = 0x0000,
	Main = 0x0001,
	Framework = 0x0002,
	Resource = 0x0004,
	Bundle = 0x0008,
	Xap = 0x0010,
	Optional = 0x0020,
};
enum StateRepository::Cache::Entity::PackageUserStatus_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_User = 0x0001,
	Field_PackageIdentity = 0x0002,
	Field_PackageFullName = 0x0004,
	Field_Status = 0x0008,
};
enum StateRepository::Cache::Entity::Protocol_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_Extension = 0x0001,
	Field_Name = 0x0002,
	Field_ProgID = 0x0004,
};
enum StateRepository::Cache::Entity::AppUriHandlerGroup_NoThrow::CacheFlags : long long int {
	Default = 0x0000,
	Field_Name = 0x0001,
	Field_Extension = 0x0002,
};
enum StateRepository::Cache::CachePackagePropertyFlags : int {
	None = 0x0000,
	DeferUpdateWhileInUse = 0x0001,
};
enum StateRepository::Cache::CompatMode : int {
	Unknown = 0x0000,
	Classic = 0x0001,
	Modern = 0x0003,
};
enum StateRepository::Cache::SRTrustLevel : int {
	Unknown = 0x0000,
	PartialTrust = 0x0001,
	FullTrust = 0x0002,
};
enum StateRepository::Cache::PackageType : int {
	Unknown = 0x0000,
	Main = 0x0001,
	Framework = 0x0002,
	Resource = 0x0004,
	Bundle = 0x0008,
	Xap = 0x0010,
	Optional = 0x0020,
};
enum StateRepository::Cache::Scope : int {
	Unknown = 0x0000,
	Machine = 0x0001,
	User = 0x0003,
};
enum StateRepository::Cache::PackageStatus : int {
	OK = 0x0000,
	LicenseIssue = 0x0001,
	ModifiedPackage = 0x0002,
	Tampered = 0x0004,
	Disabled = 0x0008,
	Offline = 0x0010,
	DeploymentInProgress = 0x0020,
	DependencyPackageIssue = 0x0040,
	DataOffline = 0x0080,
	ModifiedState = 0x0100,
	ModifiedData = 0x0200,
	RegistrationRequiredNonblocking = 0x0400,
	RegistrationRequiredBlocking = 0x0800,
	BackupInProgress = 0x1000,
	MdilBindingInProgress = 0x2000,
	ResumeRequireValidation = 0x4000,
	InPlaceUpdatePending = 0x8000,
	IsPartiallyStaged = 0x00010000,
	IsAppInstallerUpdatable = 0x00020000,
	FoldingPending = 0x00040000,
	MachineDeploymentInProgress = 0x00080000,
	MachineRegistrationRequiredNonblocking = 0x00200000,
	MachineRegistrationRequiredBlocking = 0x00400000,
	UserCustomInstallRequiredBlocking = 0x00800000,
	CustomInstallRequiredBlocking = 0x01000000,
	MachineRegisterOnRepair = 0x02000000,
	UserModifiedPackage = 0x04000000,
	MachineModifiedState = 0x08000000,
	OnDemandRegistered = 0x10000000,
	MaskMachineModified = 0x0302,
	MaskUserModified = 0x04000000,
	MaskModified = 0x04000302,
	MaskUserBad = 0x04000000,
	MaskMachineBad = 0x0307,
	MaskBad = 0x04000307,
	MaskOffline = 0x0090,
	MaskNotAvailable = 0x0098,
	MaskServicing = 0x00083020,
	MaskUnmovable = 0x000830ba,
	MaskRegistrationRequiredBlocking = 0x00400800,
	MaskNone = 0x0000,
	MaskAll = 0xff,
	MaskScope_Machine = 0x036fe05f,
	MaskScope_User = 0x14801fa0,
};
enum CacheApplicationFlags
{
	None = 0x0000,
	Reserved_00000001 = 0x0001,
	Reserved_00000002 = 0x0002,
	TrustLevelIsFullTrust = 0x0004,
	SupportsMultipleInstances = 0x0008,
	RuntimeBehaviorIsDesktopBridge = 0x0010,
	RuntimeBehaviorIsWin32alacarte = 0x0020,
	BnoIsolationIsPackage = 0x0040,
	TrustLevelIsPartialTrust = 0x0080,
	RuntimeBehaviorIsUniversal = 0x0100,
	RuntimeBehaviorIsAppSilo = 0x0200,
	AppLifecycleBehaviorIsUnmanaged = 0x0400,
	AppLifecycleBehaviorIsSystemManaged = 0x0800,
	Reserved_00001000 = 0x1000,
	Reserved_00002000 = 0x2000,
	Reserved_00004000 = 0x4000,
	Reserved_00008000 = 0x8000,
	IsConsoleSubsystem = 0x00010000
};

enum PackageOrigin
{
	Unknow = 0x0000,
	Unsigned = 0x0001,
	Inbox = 0x0002,
	Store = 0x0003,
	DeveloperUnsigned = 0x0004,
	DeveloperSigned = 0x0005,
	LineOfBusiness = 0x0006,
};
enum CachePackageFlags
{
	None = 0x0000,
	IsDevelopmentMode = 0x0001,
	HasServerApplication = 0x0002,
	HasCentennial = 0x0004,
	IsMachineRegistered = 0x0008,
	IsPackagePayloadEncrypted = 0x0010,
	IsMetadataLocationUnderSystemMetadata = 0x0020,
	HasRunFullTrustCapability = 0x0040,
	IsInRelatedSet = 0x0080,
	DoNotAllowExecution = 0x0100,
	IsNonQualifiedResourcePackage = 0x0200,
	MostRecentlyStagedInFamily = 0x0400,
	IsMsixvc = 0x0800,
	IsSingletonRegistered = 0x1000,
	NeedsSingletonRegistration = 0x2000,
	FileSystemWriteVirtualizationDisabled = 0x4000,
	RegistryWriteVirtualizationDisabled = 0x8000,
	LoaderSearchPathOverride = 0x00010000,
	IsMutablePackageDirectoryProcessed = 0x00020000,
	IsModificationPackage = 0x00040000,
	HasDependencyTargetCapability = 0x00080000,
	HasWin32alacarte = 0x00100000,
	AllowExternalLocation = 0x00200000,
	StageInPlace = 0x00400000,
	HasFullTrust = 0x00800000,
	IsSupportedUsersMultiple = 0x01000000,
	HasHostRuntime = 0x02000000,
	HasInstalledLocationVirtualization = 0x04000000,
	HasInProcessMediaExtensionCapability = 0x08000000,
	HasHostId = 0x10000000,
};

enum CachePackageFlags2{
	None = 0x0000,
	PackageIntegrityForExeSigning_EnforcementIsDefault = 0x0001,
	PackageIntegrityForExeSigning_EnforcementIsOn = 0x0002,
	PackageIntegrityForModuleSigning_EnforcementIsDefault = 0x0004,
	PackageIntegrityForModuleSigning_EnforcementIsOn = 0x0008,
	PackageIntegrityForContent_EnforcementIsDefault = 0x0010,
	PackageIntegrityForContent_EnforcementIsOn = 0x0020,
	PackageIntegrityForContent_EnforcementIsOff = 0x0040,
	Reserved_0x00000080 = 0x0080,
	IsSystemRegistered = 0x0100,
	Reserved_0x00000200 = 0x0200,
	IsUserMutablePackage = 0x0400,
	IsInstalledByElevatedUser = 0x0800,
	IsOneTimeRegistered = 0x1000,
	HasWindowsRTEKU = 0x2000,
	HasVersionSupercedencePerformed = 0x4000,
	RequiresWin32HeapCompatProfile = 0x8000,
	StageWhileInUse = 0x00010000,
	DisableInetCacheRedirection = 0x00020000,
	DisableInetCookiesRedirection = 0x00040000,
	DisableInetHistoryRedirection = 0x00080000,
};

enum CacheActivationFlags : int {
	None = 0x0000,
	SupportsMultipleUsers = 0x0001,
	IsServerApplication = 0x0002,
	TrustLevelIsFullTrust = 0x0004,
	SupportsMultipleInstances = 0x0008,
	RuntimeBehaviorIsDesktopBridge = 0x0010,
	RuntimeBehaviorIsWin32alacarte = 0x0020,
	IsConsoleSubsystem = 0x0040,
	TrustLevelIsPartialTrust = 0x0080,
	RuntimeBehaviorIsUniversal = 0x0100,
	RuntimeBehaviorIsAppSilo = 0x0200,
	AppLifecycleBehaviorIsUnmanaged = 0x0400,
	AppLifecycleBehaviorIsSystemManaged = 0x0800,
	BnoIsolationIsPackage = 0x1000,
};
enum CachePackageExtensionFlags : int {
	None = 0x0000,
	LocalizedDictionaryNeedsResolution = 0x0001,
	LocalizedDictionaryIsReady = 0x0002,
	SupportsMultipleInstances = 0x0008,
	CompatModeIsClassic = 0x1000,
	CompatModeIsModern = 0x2000,
	ScopeIsMachine = 0x4000,
	ScopeIsUser = 0x8000,
	IsConsoleSubsystem = 0x00010000,
};
enum CacheApplicationExtensionFlags : int {
	None = 0x0000,
	LocalizedDictionaryNeedsResolution = 0x0001,
	LocalizedDictionaryIsReady = 0x0002,
	SupportsMultipleInstances = 0x0008,
	CompatModeIsClassic = 0x1000,
	CompatModeIsModern = 0x2000,
	ScopeIsMachine = 0x4000,
	ScopeIsUser = 0x8000,
	DoesNotSupportMultipleInstances = 0x00010000,
	IsExplicitProgId = 0x00040000,
};
*/