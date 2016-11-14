//-----------------------------------------------------------------------------------------------------------------
// Root.
//-----------------------------------------------------------------------------------------------------------------

export interface PeStruct {
	data: DataView;
	// Headers
	dosHeader?: DosHeader;
	peSignature?: U4Field;
	fileHeader?: FileHeader;
	optionalHeader?: OptionalHeader;
	sectionHeaders?: FileDataVec<SectionHeader>;
	// Metadata
	cliHeader?: CliHeader;
	mdRoot?: MdRoot;
	mdsStrings?: FileDataVec<NullTerminatedUtf8StringField>;
	mdsUS?: FileDataVec<MdsUsItem>;
	mdsGuid?: FileDataVec<FileData>;
	mdsBlob?: FileDataVec<MdsBlobItem>;
	mdTableHeader?: MdTableHeader;
	mdTableRows?: number[];
	// Metadata - tables
	mdtModule?: FileDataVec<MdtModuleItem>;
	mdtTypeRef?: FileDataVec<MdtTypeRefItem>;
	mdtTypeDef?: FileDataVec<MdtTypeDefItem>;
	mdtFieldPtr?: FileDataVec<MdtFieldPtrItem>;
	mdtField?: FileDataVec<MdtFieldItem>;
	mdtMethodPtr?: FileDataVec<MdtMethodPtrItem>;
	mdtMethodDef?: FileDataVec<MdtMethodDefItem>;
	mdtParamPtr?: FileDataVec<MdtParamPtrItem>;
	mdtParam?: FileDataVec<MdtParamItem>;
	mdtInterfaceImpl?: FileDataVec<MdtInterfaceImplItem>;
	mdtMemberRef?: FileDataVec<MdtMemberRefItem>;
	mdtConstant?: FileDataVec<MdtConstantItem>;
	mdtCustomAttribute?: FileDataVec<MdtCustomAttributeItem>;
	mdtFieldMarshal?: FileDataVec<MdtFieldMarshalItem>;
	mdtDeclSecurity?: FileDataVec<MdtDeclSecurityItem>;
	mdtClassLayout?: FileDataVec<MdtClassLayoutItem>;
	mdtFieldLayout?: FileDataVec<MdtFieldLayoutItem>;
	mdtStandAloneSig?: FileDataVec<MdtStandAloneSigItem>;
	mdtEventMap?: FileDataVec<MdtEventMapItem>;
	mdtEventPtr?: FileDataVec<MdtEventPtrItem>;
	mdtEvent?: FileDataVec<MdtEventItem>;
	mdtPropertyMap?: FileDataVec<MdtPropertyMapItem>;
	mdtPropertyPtr?: FileDataVec<MdtPropertyPtrItem>;
	mdtProperty?: FileDataVec<MdtPropertyItem>;
	mdtMethodSemantics?: FileDataVec<MdtMethodSemanticsItem>;
	mdtMethodImpl?: FileDataVec<MdtMethodImplItem>;
	mdtModuleRef?: FileDataVec<MdtModuleRefItem>;
	mdtTypeSpec?: FileDataVec<MdtTypeSpecItem>;
	mdtImplMap?: FileDataVec<MdtImplMapItem>;
	mdtFieldRVA?: FileDataVec<MdtFieldRVAItem>;
	mdtENCLog?: FileDataVec<MdtENCLogItem>;
	mdtENCMap?: FileDataVec<MdtENCMapItem>;
	mdtAssembly?: FileDataVec<MdtAssemblyItem>;
	mdtAssemblyProcessor?: FileDataVec<MdtAssemblyProcessorItem>;
	mdtAssemblyOS?: FileDataVec<MdtAssemblyOSItem>;
	mdtAssemblyRef?: FileDataVec<MdtAssemblyRefItem>;
	mdtAssemblyRefProcessor?: FileDataVec<MdtAssemblyRefProcessorItem>;
	mdtAssemblyRefOS?: FileDataVec<MdtAssemblyRefOSItem>;
	mdtFile?: FileDataVec<MdtFileItem>;
	mdtExportedType?: FileDataVec<MdtExportedTypeItem>;
	mdtManifestResource?: FileDataVec<MdtManifestResourceItem>;
	mdtNestedClass?: FileDataVec<MdtNestedClassItem>;
	mdtGenericParam?: FileDataVec<MdtGenericParamItem>;
	mdtMethodSpec?: FileDataVec<MdtMethodSpecItem>;
	mdtGenericParamConstraint?: FileDataVec<MdtGenericParamConstraintItem>;
}

//-----------------------------------------------------------------------------------------------------------------
// Headers.
//-----------------------------------------------------------------------------------------------------------------

export interface DosHeader extends FileData {
	e_magic: U2Field;
	e_cblp: U2Field;
	e_cp: U2Field;
	e_crlc: U2Field;
	e_cparhdr: U2Field;
	e_minalloc: U2Field;
	e_maxalloc: U2Field;
	e_ss: U2Field;
	e_sp: U2Field;
	e_csum: U2Field;
	e_ip: U2Field;
	e_cs: U2Field;
	e_lfarlc: U2Field;
	e_ovno: U2Field;
	e_res: FileData;
	e_oemid: U2Field;
	e_oeminfo: U2Field;
	e_res2: FileData;
	e_lfanew: U4Field;
}

export const dosSignature = 0x5A4D;
export const ntSignature = 0x00004550;

export interface FileHeader extends FileData {
	Machine: E2Field<FileMachine>;
	NumberOfSections: U2Field;
	TimeDateStamp: U4Field;
	PointerToSymbolTable: U4Field;
	NumberOfSymbols: U4Field;
	SizeOfOptionalHeader: U2Field;
	Characteristics: E2Field<FileAttr>;
}

export enum FileMachine {
	IMAGE_FILE_MACHINE_UNKNOWN = 0,
	IMAGE_FILE_MACHINE_I386 = 0x014c,
	IMAGE_FILE_MACHINE_R3000 = 0x0162,
	IMAGE_FILE_MACHINE_R4000 = 0x0166,
	IMAGE_FILE_MACHINE_R10000 = 0x0168,
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,
	IMAGE_FILE_MACHINE_ALPHA = 0x0184,
	IMAGE_FILE_MACHINE_SH3 = 0x01a2,
	IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
	IMAGE_FILE_MACHINE_SH3E = 0x01a4,
	IMAGE_FILE_MACHINE_SH4 = 0x01a6,
	IMAGE_FILE_MACHINE_SH5 = 0x01a8,
	IMAGE_FILE_MACHINE_ARM = 0x01c0,
	IMAGE_FILE_MACHINE_THUMB = 0x01c2,
	IMAGE_FILE_MACHINE_ARMNT = 0x01c4,
	IMAGE_FILE_MACHINE_AM33 = 0x01d3,
	IMAGE_FILE_MACHINE_POWERPC = 0x01F0,
	IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
	IMAGE_FILE_MACHINE_IA64 = 0x0200,
	IMAGE_FILE_MACHINE_MIPS16 = 0x0266,
	IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,
	IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
	IMAGE_FILE_MACHINE_TRICORE = 0x0520,
	IMAGE_FILE_MACHINE_CEF = 0x0CEF,
	IMAGE_FILE_MACHINE_EBC = 0x0EBC,
	IMAGE_FILE_MACHINE_AMD64 = 0x8664,
	IMAGE_FILE_MACHINE_M32R = 0x9041,
	IMAGE_FILE_MACHINE_CEE = 0xC0EE,
}

export enum FileAttr {
	IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
	IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
	IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
	IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
	IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
	IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
	IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
	IMAGE_FILE_32BIT_MACHINE = 0x0100,
	IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
	IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
	IMAGE_FILE_SYSTEM = 0x1000,
	IMAGE_FILE_DLL = 0x2000,
	IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
	IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
}

export const sizeOfOptHdr32 = 0xE0;
export const sizeOfOptHdr64 = 0xF0;

export interface DataDirectory extends FileData {
	Rva: U4Field;
	Size: U4Field;
}

export interface OptionalHeader extends FileData {
	//
	// Standard fields.
	//
	Magic: U2Field;
	MajorLinkerVersion: U1Field;
	MinorLinkerVersion: U1Field;
	SizeOfCode: U4Field;
	SizeOfInitializedData: U4Field;
	SizeOfUninitializedData: U4Field;
	AddressOfEntryPoint: U4Field;
	BaseOfCode: U4Field;

	//
	// NT additional fields.
	//
	SectionAlignment: U4Field;
	FileAlignment: U4Field;
	MajorOperatingSystemVersion: U2Field;
	MinorOperatingSystemVersion: U2Field;
	MajorImageVersion: U2Field;
	MinorImageVersion: U2Field;
	MajorSubsystemVersion: U2Field;
	MinorSubsystemVersion: U2Field;
	Win32VersionValue: U4Field;
	SizeOfImage: U4Field;
	SizeOfHeaders: U4Field;
	CheckSum: U4Field;
	Subsystem: E2Field<Subsystem>;
	DllCharacteristics: E2Field<DllAttr>;

	LoaderFlags: U4Field;
	NumberOfRvaAndSizes: U4Field;

	DataDirectories: FileDataVec<DataDirectory>;
}

export interface OptionalHeader32 extends OptionalHeader {
	//
	// Standard fields.
	//
	BaseOfData: U4Field;
	//
	// NT additional fields.
	//
	ImageBase: U4Field;

	SizeOfStackReserve: U4Field;
	SizeOfStackCommit: U4Field;
	SizeOfHeapReserve: U4Field;
	SizeOfHeapCommit: U4Field;
}

export interface OptionalHeader64 extends OptionalHeader {
	//
	// NT additional fields.
	//
	ImageBase: U8Field;

	SizeOfStackReserve: U8Field;
	SizeOfStackCommit: U8Field;
	SizeOfHeapReserve: U8Field;
	SizeOfHeapCommit: U8Field;
}

export const ntOptHdr32Magic = 0x010B;
export const ntOptHdr64Magic = 0x020B;
export const numberOfDataDirectories = 16;

export enum Subsystem {
	IMAGE_SUBSYSTEM_UNKNOWN = 0,
	IMAGE_SUBSYSTEM_NATIVE = 1,
	IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
	IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
	IMAGE_SUBSYSTEM_OS2_CUI = 5,
	IMAGE_SUBSYSTEM_POSIX_CUI = 7,
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
	IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
	IMAGE_SUBSYSTEM_EFI_ROM = 13,
	IMAGE_SUBSYSTEM_XBOX = 14,
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
}

export enum DllAttr {
	IMAGE_LIBRARY_PROCESS_INIT = 0x0001,
	IMAGE_LIBRARY_PROCESS_TERM = 0x0002,
	IMAGE_LIBRARY_THREAD_INIT = 0x0004,
	IMAGE_LIBRARY_THREAD_TERM = 0x0008,
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
	IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
	IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
	IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
}

export enum DataDirectoryIndex {
	Export = 0,
	Import = 1,
	Resource = 2,
	Exception = 3,
	Security = 4,
	Basereloc = 5,
	Debug = 6,
	Copyright = 7,
	Architecture = 7,
	Globalptr = 8,
	Tls = 9,
	LoadConfig = 10,
	BoundImport = 11,
	Iat = 12,
	DelayImport = 13,
	ComDescriptor = 14,
}

export interface SectionHeader extends FileData {
	Name: FixedSizeAsciiStringField;
	VirtualSize: U4Field;
	VirtualAddress: U4Field;
	SizeOfRawData: U4Field;
	PointerToRawData: U4Field;
	PointerToRelocations: U4Field;
	PointerToLinenumbers: U4Field;
	NumberOfRelocations: U2Field;
	NumberOfLinenumbers: U2Field;
	Characteristics: E4Field<SectionAttr>;
}

export enum SectionAttr {
	IMAGE_SCN_SCALE_INDEX = 0x00000001,
	IMAGE_SCN_TYPE_NO_PAD = 0x00000008,

	IMAGE_SCN_CNT_CODE = 0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,

	IMAGE_SCN_LNK_OTHER = 0x00000100,
	IMAGE_SCN_LNK_INFO = 0x00000200,
	IMAGE_SCN_LNK_REMOVE = 0x00000800,
	IMAGE_SCN_LNK_COMDAT = 0x00001000,

	IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000,
	IMAGE_SCN_GPREL = 0x00008000,
	IMAGE_SCN_MEM_FARDATA = 0x00008000,

	IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
	IMAGE_SCN_MEM_16BIT = 0x00020000,
	IMAGE_SCN_MEM_LOCKED = 0x00040000,
	IMAGE_SCN_MEM_PRELOAD = 0x00080000,

	al__Mask = 0x00F00000,
	al_IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
	al_IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
	al_IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
	al_IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
	al_IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
	al_IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
	al_IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
	al_IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
	al_IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
	al_IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
	al_IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
	al_IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
	al_IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
	al_IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,

	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
	IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
	IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
	IMAGE_SCN_MEM_SHARED = 0x10000000,
	IMAGE_SCN_MEM_EXECUTE = 0x20000000,
	IMAGE_SCN_MEM_READ = 0x40000000,
	IMAGE_SCN_MEM_WRITE = 0x80000000,
}

//-----------------------------------------------------------------------------------------------------------------
// Metadata.
//-----------------------------------------------------------------------------------------------------------------

export interface CliHeader extends FileData {
	cb: U4Field;
	MajorRuntimeVersion: U2Field;
	MinorRuntimeVersion: U2Field;
	MetaData: DataDirectory;
	Flags: E4Field<ComImageAttr>;
	EntryPointToken: U4Field;
	Resources: DataDirectory;
	StrongNameSignature: DataDirectory;
	CodeManagerTable: DataDirectory;
	VTableFixups: DataDirectory;
	ExportAddressTableJumps: DataDirectory;
	ManagedNativeHeader: DataDirectory;
}

export enum ComImageAttr {
	COMIMAGE_FLAGS_ILONLY = 0x00000001,
	COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002,
	COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004,
	COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008,
	COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010,
	COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000,
}

export interface MdRoot extends FileData {
	Signature: U4Field;
	MajorVersion: U2Field;
	MinorVersion: U2Field;
	Reserved: U4Field;
	VersionLength: U4Field;
	Version: FixedSizeUtf8StringField;
	VersionPadding: FileData;
	Flags: U2Field;
	NumberOfStreams: U2Field;
	StreamHeaders: FileDataVec<MdStreamHeader>;
}

export const mdSignature = 0x424A5342;

export interface MdStreamHeader extends FileData {
	Offset: U4Field;
	Size: U4Field;
	Name: NullTerminatedUtf8StringField;
	Padding: FileData;
}

export const mdsNameTable = "#~";
export const mdsNameStrings = "#Strings";
export const mdsNameUS = "#US";
export const mdsNameGuid = "#GUID";
export const mdsNameBlob = "#Blob";

export interface MdsUsItem extends FileData {
	compressedSize: CompressedUintField;
	userString: FixedSizeUnicodeStringField;
	suffix: FileData;
}

export interface MdsBlobItem extends FileData {
	compressedSize: CompressedUintField;
	data: FileData;
}

export interface MdTableHeader extends FileData {
	Reserved: U4Field;
	MajorVersion: U1Field;
	MinorVersion: U1Field;
	HeapSizes: E1Field<MdHeapSizeAttr>;
	Reserved2: U1Field;
	Valid: U8Field;
	Sorted: U8Field;
	Rows: FileDataVec<U4Field>;
}

export enum MdHeapSizeAttr {
	Strings = 0x01,
	Guid = 0x02,
	Blob = 0x04,
}

export enum MdTableIndex {
	Module = 0x00,
	TypeRef = 0x01,
	TypeDef = 0x02,
	FieldPtr = 0x03,
	Field = 0x04,
	MethodPtr = 0x05,
	MethodDef = 0x06,
	ParamPtr = 0x07,
	Param = 0x08,
	InterfaceImpl = 0x09,
	MemberRef = 0x0A,
	Constant = 0x0B,
	CustomAttribute = 0x0C,
	FieldMarshal = 0x0D,
	DeclSecurity = 0x0E,
	ClassLayout = 0x0F,
	FieldLayout = 0x10,
	StandAloneSig = 0x11,
	EventMap = 0x12,
	EventPtr = 0x13,
	Event = 0x14,
	PropertyMap = 0x15,
	PropertyPtr = 0x16,
	Property = 0x17,
	MethodSemantics = 0x18,
	MethodImpl = 0x19,
	ModuleRef = 0x1A,
	TypeSpec = 0x1B,
	ImplMap = 0x1C,
	FieldRVA = 0x1D,
	ENCLog = 0x1E,
	ENCMap = 0x1F,
	Assembly = 0x20,
	AssemblyProcessor = 0x21,
	AssemblyOS = 0x22,
	AssemblyRef = 0x23,
	AssemblyRefProcessor = 0x24,
	AssemblyRefOS = 0x25,
	File = 0x26,
	ExportedType = 0x27,
	ManifestResource = 0x28,
	NestedClass = 0x29,
	GenericParam = 0x2A,
	MethodSpec = 0x2B,
	GenericParamConstraint = 0x2C,

	String = 0x70,
}

export const numberOfMdTables = 45;

export interface MdtModuleItem extends FileData {
	Generation: U2Field;
	Name: MdsStringsField;
	Mvid: MdsGuidField;
	EncId: MdsGuidField;
	EncBaseId: MdsGuidField;
}

export interface MdtTypeRefItem extends FileData {
	ResolutionScope: MdCodedTokenField;  // ResolutionScope
	Name: MdsStringsField;
	Namespace: MdsStringsField;
}

export interface MdtTypeDefItem extends FileData {
	Flags: E4Field<CorTypeAttr>;
	Name: MdsStringsField;
	Namespace: MdsStringsField;
	Extends: MdCodedTokenField;
	FieldList: MdtRidField;
	MethodList: MdtRidField;
}

export interface MdtFieldPtrItem extends FileData {
	Field: MdtRidField;
}

export interface MdtFieldItem extends FileData {
	Flags: E2Field<CorFieldAttr>;
	Name: MdsStringsField;
	Signature: MdsBlobField;
}

export interface MdtMethodPtrItem extends FileData {
	Method: MdtRidField;
}

export interface MdtMethodDefItem extends FileData {
	RVA: U4Field;
	ImplFlags: E2Field<CorMethodImpl>;
	Flags: E2Field<CorMethodAttr>;
	Name: MdsStringsField;
	Signature: MdsBlobField;
	ParamList: MdtRidField;
}

export interface MdtParamPtrItem extends FileData {
	Param: MdtRidField;
}

export interface MdtParamItem extends FileData {
	Flags: E2Field<CorParamAttr>;
	Sequence: U2Field;
	Name: MdsStringsField;
}

export interface MdtInterfaceImplItem extends FileData {
	Class: MdtRidField;
	Interface: MdCodedTokenField;
}

export interface MdtMemberRefItem extends FileData {
	Class: MdCodedTokenField;
	Name: MdsStringsField;
	Signature: MdsBlobField;
}

export interface MdtConstantItem extends FileData {
	Type: E1Field<CorElementType>;
	PaddingZero: U1Field;
	Parent: MdCodedTokenField;
	Value: MdsBlobField;
}

export interface MdtCustomAttributeItem extends FileData {
	Parent: MdCodedTokenField;
	Type: MdCodedTokenField;
	Value: MdsBlobField;
}

export interface MdtFieldMarshalItem extends FileData {
	Parent: MdCodedTokenField;
	NativeType: MdsBlobField;
}

export interface MdtDeclSecurityItem extends FileData {
	Action: E2Field<CorDeclSecurity>;
	Parent: MdCodedTokenField;
	PermissionSet: MdsBlobField;
}

export interface MdtClassLayoutItem extends FileData {
	PackingSize: U2Field;
	ClassSize: U4Field;
	Parent: MdtRidField;
}

export interface MdtFieldLayoutItem extends FileData {
	OffSet: U4Field;
	Field: MdtRidField;
}

export interface MdtStandAloneSigItem extends FileData {
	Signature: MdsBlobField;
}

export interface MdtEventMapItem extends FileData {
	Parent: MdtRidField;
	EventList: MdtRidField;
}

export interface MdtEventPtrItem extends FileData {
	Event: MdtRidField;
}

export interface MdtEventItem extends FileData {
	EventFlags: E2Field<CorEventAttr>;
	Name: MdsStringsField;
	EventType: MdCodedTokenField;
}

export interface MdtPropertyMapItem extends FileData {
	Parent: MdtRidField;
	PropertyList: MdtRidField;
}

export interface MdtPropertyPtrItem extends FileData {
	Property: MdtRidField;
}

export interface MdtPropertyItem extends FileData {
	PropFlags: E2Field<CorPropertyAttr>;
	Name: MdsStringsField;
	Type: MdsBlobField;
}

export interface MdtMethodSemanticsItem extends FileData {
	Semantic: E2Field<CorMethodSemanticsAttr>;
	Method: MdtRidField;
	Association: MdCodedTokenField;
}

export interface MdtMethodImplItem extends FileData {
	Class: MdtRidField;
	MethodBody: MdCodedTokenField;
	MethodDeclaration: MdCodedTokenField;
}

export interface MdtModuleRefItem extends FileData {
	Name: MdsStringsField;
}

export interface MdtTypeSpecItem extends FileData {
	Signature: MdsBlobField;
}

export interface MdtImplMapItem extends FileData {
	MappingFlags: E2Field<CorPinvokeMap>;
	MemberForwarded: MdCodedTokenField;
	ImportName: MdsStringsField;
	ImportScope: MdtRidField;
}

export interface MdtFieldRVAItem extends FileData {
	RVA: U4Field;
	Field: MdtRidField;
}

export interface MdtENCLogItem extends FileData {
	Token: U4Field;
	FuncCode: U4Field;
}

export interface MdtENCMapItem extends FileData {
	Token: U4Field;
}

export interface MdtAssemblyItem extends FileData {
	HashAlgId: E4Field<AssemblyHashAlgorithm>;
	MajorVersion: U2Field;
	MinorVersion: U2Field;
	BuildNumber: U2Field;
	RevisionNumber: U2Field;
	Flags: E4Field<CorAssemblyFlags>;
	PublicKey: MdsBlobField;
	Name: MdsStringsField;
	Locale: MdsStringsField;
}

export interface MdtAssemblyProcessorItem extends FileData {
	Processor: U4Field;
}

export interface MdtAssemblyOSItem extends FileData {
	OSPlatformID: U4Field;
	OSMajorVersion: U4Field;
	OSMinorVersion: U4Field;
}

export interface MdtAssemblyRefItem extends FileData {
	MajorVersion: U2Field;
	MinorVersion: U2Field;
	BuildNumber: U2Field;
	RevisionNumber: U2Field;
	Flags: E4Field<CorAssemblyFlags>;
	PublicKeyOrToken: MdsBlobField;
	Name: MdsStringsField;
	Locale: MdsStringsField;
	HashValue: MdsBlobField;
}

export interface MdtAssemblyRefProcessorItem extends FileData {
	Processor: U4Field;
	AssemblyRef: MdtRidField;
}

export interface MdtAssemblyRefOSItem extends FileData {
	OSPlatformID: U4Field;
	OSMajorVersion: U4Field;
	OSMinorVersion: U4Field;
	AssemblyRef: MdtRidField;
}

export interface MdtFileItem extends FileData {
	Flags: E4Field<CorFileFlags>;
	Name: MdsStringsField;
	HashValue: MdsBlobField;
}

export interface MdtExportedTypeItem extends FileData {
	Flags: E4Field<CorTypeAttr>;
	TypeDefId: U4Field;
	TypeName: MdsStringsField;
	TypeNamespace: MdsStringsField;
	Implementation: MdCodedTokenField;
}

export interface MdtManifestResourceItem extends FileData {
	Offset: U4Field;
	Flags: E4Field<CorManifestResourceFlags>;
	Name: MdsStringsField;
	Implementation: MdCodedTokenField;
}

export interface MdtNestedClassItem extends FileData {
	NestedClass: MdtRidField;
	EnclosingClass: MdtRidField;
}

export interface MdtGenericParamItem extends FileData {
	Number: U2Field;
	Flags: E2Field<CorGenericParamAttr>;
	Owner: MdCodedTokenField;
	Name: MdsStringsField;
}

export interface MdtMethodSpecItem extends FileData {
	Method: MdCodedTokenField;
	Instantiation: MdsBlobField;
}

export interface MdtGenericParamConstraintItem extends FileData {
	Owner: MdtRidField;
	Constraint: MdCodedTokenField;
}

export enum AssemblyHashAlgorithm {
	None = 0x0000,
	MD5 = 0x8003,  // Reserved
	SHA1 = 0x8004,
}

export enum CorAssemblyFlags {
	PublicKey = 0x0001,

	pa__Mask = 0x0070,
	pa_ProcessorArchitectureNone = 0x0000,
	pa_ProcessorArchitectureMsil = 0x0010,
	pa_ProcessorArchitectureX86 = 0x0020,
	pa_ProcessorArchitectureIa64 = 0x0030,
	pa_ProcessorArchitectureAmd64 = 0x0040,

	ProcessorArchitectureSpecified = 0x0080,

	EnableJitcompileTracking = 0x8000,
	DisableJitcompileOptimizer = 0x4000,

	Retargetable = 0x0100,
}

export enum CorEventAttr {
	SpecialName = 0x0200,
	RtSpecialName = 0x0400,
}

export enum CorFieldAttr {
	fa__Mask = 0x0007,
	fa_PrivateScope = 0x0000,
	fa_Private = 0x0001,
	fa_FamAndAssem = 0x0002,
	fa_Assembly = 0x0003,
	fa_Family = 0x0004,
	fa_FamOrAssem = 0x0005,
	fa_Public = 0x0006,

	Static = 0x0010,
	InitOnly = 0x0020,
	Literal = 0x0040,
	NotSerialized = 0x0080,

	SpecialName = 0x0200,

	PinvokeImpl = 0x2000,

	RtSpecialName = 0x0400,
	HasFieldMarshal = 0x1000,
	HasDefault = 0x8000,
	HasFieldRva = 0x0100,
}

export enum CorFileFlags {
	ContainsMetaData = 0x0000,
	ContainsNoMetaData = 0x0001,
}

export enum CorGenericParamAttr {
	v__Mask = 0x0003,
	v_NonVariant = 0x0000,
	v_Covariant = 0x0001,
	v_Contravariant = 0x0002,

	NoSpecialConstraint = 0x0000,
	ReferenceTypeConstraint = 0x0004,
	NotNullableValueTypeConstraint = 0x0008,
	DefaultConstructorConstraint = 0x0010,
}

export enum CorPinvokeMap {
	NoMangle = 0x0001,
	cs__Mask = 0x0006,
	cs_CharSetNotSpec = 0x0000,
	cs_CharSetAnsi = 0x0002,
	cs_CharSetUnicode = 0x0004,
	cs_CharSetAuto = 0x0006,

	bf__Mask = 0x0030,
	bf_BestFitUseAssem = 0x0000,
	bf_BestFitEnabled = 0x0010,
	bf_BestFitDisabled = 0x0020,

	touc__Mask = 0x3000,
	touc_ThrowOnUnmappableCharUseAssem = 0x0000,
	touc_ThrowOnUnmappableCharEnabled = 0x1000,
	touc_ThrowOnUnmappableCharDisabled = 0x2000,

	SupportsLastError = 0x0040,

	cc__Mask = 0x0700,
	cc_CallConvWinapi = 0x0100,
	cc_CallConvCdecl = 0x0200,
	cc_CallConvStdcall = 0x0300,
	cc_CallConvThiscall = 0x0400,
	cc_CallConvFastcall = 0x0500,
}

export enum CorManifestResourceFlags {
	v__Mask = 0x0007,
	v_Public = 0x0001,
	v_Private = 0x0002,
}

export enum CorMethodAttr {
	ma__Mask = 0x0007,
	ma_PrivateScope = 0x0000,
	ma_Private = 0x0001,
	ma_FamAndAssem = 0x0002,
	ma_Assem = 0x0003,
	ma_Family = 0x0004,
	ma_FamOrAssem = 0x0005,
	ma_Public = 0x0006,

	Static = 0x0010,
	Final = 0x0020,
	Virtual = 0x0040,
	HideBySig = 0x0080,

	vl__Mask = 0x0100,
	vl_ReuseSlot = 0x0000,
	vl_NewSlot = 0x0100,

	CheckAccessOnOverride = 0x0200,
	Abstract = 0x0400,
	SpecialName = 0x0800,

	PInvokeImpl = 0x2000,
	UnmanagedExport = 0x0008,

	RtSpecialName = 0x1000,
	HasSecurity = 0x4000,
	RequireSecObject = 0x8000,
}

export enum CorMethodImpl {
	ct__Mask = 0x0003,
	ct_IL = 0x0000,
	ct_Native = 0x0001,
	ct_OptIL = 0x0002,
	ct_Runtime = 0x0003,

	m__Mask = 0x0004,
	m_Unmanaged = 0x0004,
	m_Managed = 0x0000,

	ForwardRef = 0x0010,
	PreserveSig = 0x0080,

	InternalCall = 0x1000,

	Synchronized = 0x0020,
	NoInlining = 0x0008,
}

export enum CorMethodSemanticsAttr {
	Setter = 0x0001,
	Getter = 0x0002,
	Other = 0x0004,
	AddOn = 0x0008,
	RemoveOn = 0x0010,
	Fire = 0x0020,
}

export enum CorParamAttr {
	In = 0x0001,
	Out = 0x0002,
	Optional = 0x0010,

	HasDefault = 0x1000,
	HasFieldMarshal = 0x2000,

	Unused = 0xcfe0,
}

export enum CorPropertyAttr {
	SpecialName = 0x0200,

	RtSpecialName = 0x0400,
	HasDefault = 0x1000,

	Unused = 0xe9ff,
}

export enum CorTypeAttr {
	v__Mask = 0x00000007,
	v_NotPublic = 0x00000000,
	v_Public = 0x00000001,
	v_NestedPublic = 0x00000002,
	v_NestedPrivate = 0x00000003,
	v_NestedFamily = 0x00000004,
	v_NestedAssembly = 0x00000005,
	v_NestedFamAndAssem = 0x00000006,
	v_NestedFamOrAssem = 0x00000007,

	l__Mask = 0x00000018,
	l_AutoLayout = 0x00000000,
	l_SequentialLayout = 0x00000008,
	l_ExplicitLayout = 0x00000010,

	cs__Mask = 0x00000060,
	cs_Class = 0x00000000,
	cs_Interface = 0x00000020,

	Abstract = 0x00000080,
	Sealed = 0x00000100,
	SpecialName = 0x00000400,

	Import = 0x00001000,
	Serializable = 0x00002000,
	WindowsRuntime = 0x00004000,

	sf__Mask = 0x00030000,
	sf_AnsiClass = 0x00000000,
	sf_UnicodeClass = 0x00010000,
	sf_AutoClass = 0x00020000,
	sf_CustomFormatClass = 0x00030000,
	CustomFormatMask = 0x00C00000,

	BeforeFieldInit = 0x00100000,
	Forwarder = 0x00200000,

	RtSpecialName = 0x00000800,
	HasSecurity = 0x00040000,
}

export enum CorDeclSecurity {
	ActionNil = 0x0000,
	Request = 0x0001,
	Demand = 0x0002,
	Assert = 0x0003,
	Deny = 0x0004,
	PermitOnly = 0x0005,
	LinktimeCheck = 0x0006,
	InheritanceCheck = 0x0007,
	RequestMinimum = 0x0008,
	RequestOptional = 0x0009,
	RequestRefuse = 0x000a,
	PrejitGrant = 0x000b,
	PrejitDenied = 0x000c,
	NonCasDemand = 0x000d,
	NonCasLinkDemand = 0x000e,
	NonCasInheritance = 0x000f,
}

export enum CorElementType {
	End = 0x00,
	Void = 0x01,
	Boolean = 0x02,
	Char = 0x03,
	I1 = 0x04,
	U1 = 0x05,
	I2 = 0x06,
	U2 = 0x07,
	I4 = 0x08,
	U4 = 0x09,
	I8 = 0x0A,
	U8 = 0x0B,
	R4 = 0x0C,
	R8 = 0x0D,
	String = 0x0E,

	Ptr = 0x0F,
	ByRef = 0x10,

	ValueType = 0x11,
	Class = 0x12,
	Var = 0x13,
	Array = 0x14,
	GenericInst = 0x15,
	TypedByRef = 0x16,

	I = 0x18,
	U = 0x19,
	FnPtr = 0x1B,
	Object = 0x1C,
	SzArray = 0x1D,

	MVar = 0x1E,

	CModReqd = 0x1F,
	CModOpt = 0x20,
	Internal = 0x21,

	Modifier = 0x40,
	Sentinel = 0x01 | Modifier,
	Pinned = 0x05 | Modifier,
	R4HFA = 0x06 | Modifier,
	R8HFA = 0x07 | Modifier,
}

//-----------------------------------------------------------------------------------------------------------------
// Common Structures.
//-----------------------------------------------------------------------------------------------------------------

export interface FileData { _off: number; _sz: number; }

export interface NumberField extends FileData { value: number; }
export interface U1Field extends NumberField { }
export interface U2Field extends NumberField { }
export interface U4Field extends NumberField { }
export interface U8Field extends FileData { high: number; low: number; }
export interface CompressedUintField extends NumberField { }
export interface MdtRidField extends NumberField { }
export interface MdsStringsField extends NumberField { }
export interface MdsGuidField extends NumberField { }
export interface MdsBlobField extends NumberField { }
export interface MdCodedTokenField extends FileData {
	tid: MdTableIndex;
	rid: number;
}

export interface StringField extends FileData { value: string; }
export interface FixedSizeAsciiStringField extends StringField { }
export interface FixedSizeUtf8StringField extends StringField { }
export interface NullTerminatedAsciiStringField extends StringField { }
export interface NullTerminatedUtf8StringField extends StringField { }
export interface FixedSizeUnicodeStringField extends StringField { }

export interface E1Field<T> extends FileData { value: T; }
export interface E2Field<T> extends FileData { value: T; }
export interface E4Field<T> extends FileData { value: T; }

export interface FileDataVec<T extends FileData> extends FileData { values: T[]; }
