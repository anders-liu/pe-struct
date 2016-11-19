/// <reference path="./struct.ts" />
/// <reference path="./util.ts" />
/// <reference path="./error.ts" />

import * as PE from "./struct";
import * as U from "./util";
import * as E from "./error";

export function load(buf: ArrayBuffer): PE.PeStruct {
	const d = new DataView(buf);
	const pe: PE.PeStruct = {
		data: d
	};

	Object.assign(pe, loadHeaders(d));

	if (U.hasMetadata(pe))
		Object.assign(pe, loadMetadata(pe));

	return pe;
}

function loadHeaders(d: DataView) {
	chk_fsz(d.byteLength);

	let pos = 0;
	const dosHeader = loadDosHeaders(d, pos);

	pos = dosHeader.e_lfanew.value;
	const peSignature = loadU4(d, pos);

	if (peSignature.value != PE.ntSignature)
		err(E.PeErrorType.InvalidPeSignature, peSignature);

	pos += peSignature._sz;
	const fileHeader = loadFileHeader(d, pos);

	pos += fileHeader._sz;
	const optionalHeader = loadOptionalHeader(d, pos);

	if (fileHeader.SizeOfOptionalHeader.value != optionalHeader._sz)
		err(E.PeErrorType.InvalidSizeOfOptionalHeader, fileHeader.SizeOfOptionalHeader);

	pos += optionalHeader._sz;
	const sectionHeaders = loadSectionHeaders(d, pos, fileHeader.NumberOfSections.value);

	return {
		dosHeader,
		peSignature,
		fileHeader,
		optionalHeader,
		sectionHeaders,
	};
}

function loadDosHeaders(d: DataView, _off: number): PE.DosHeader {
	let pos = _off;

	const e_magic = loadU2(d, pos);
	pos += e_magic._sz;

	if (e_magic.value != PE.dosSignature)
		err(E.PeErrorType.InvalidDosSignature, e_magic);

	const e_cblp = loadU2(d, pos);
	pos += e_cblp._sz;

	const e_cp = loadU2(d, pos);
	pos += e_cp._sz;

	const e_crlc = loadU2(d, pos);
	pos += e_crlc._sz;

	const e_cparhdr = loadU2(d, pos);
	pos += e_cparhdr._sz;

	const e_minalloc = loadU2(d, pos);
	pos += e_minalloc._sz;

	const e_maxalloc = loadU2(d, pos);
	pos += e_maxalloc._sz;

	const e_ss = loadU2(d, pos);
	pos += e_ss._sz;

	const e_sp = loadU2(d, pos);
	pos += e_sp._sz;

	const e_csum = loadU2(d, pos);
	pos += e_csum._sz;

	const e_ip = loadU2(d, pos);
	pos += e_ip._sz;

	const e_cs = loadU2(d, pos);
	pos += e_cs._sz;

	const e_lfarlc = loadU2(d, pos);
	pos += e_lfarlc._sz;

	const e_ovno = loadU2(d, pos);
	pos += e_ovno._sz;

	const e_res = loadFileData(d, pos, 2 * 4);
	pos += e_res._sz;

	const e_oemid = loadU2(d, pos);
	pos += e_oemid._sz;

	const e_oeminfo = loadU2(d, pos);
	pos += e_oeminfo._sz;

	const e_res2 = loadFileData(d, pos, 2 * 10);
	pos += e_res2._sz;

	const e_lfanew = loadU4(d, pos);
	pos += e_lfanew._sz;

	chk_fp(d, e_lfanew, 4);

	return {
		_off, _sz: pos - _off,
		e_magic,
		e_cblp,
		e_cp,
		e_crlc,
		e_cparhdr,
		e_minalloc,
		e_maxalloc,
		e_ss,
		e_sp,
		e_csum,
		e_ip,
		e_cs,
		e_lfarlc,
		e_ovno,
		e_res,
		e_oemid,
		e_oeminfo,
		e_res2,
		e_lfanew,
	};
}

function loadFileHeader(d: DataView, _off: number): PE.FileHeader {
	let pos = _off;

	const Machine = loadE2<PE.FileMachine>(d, pos);
	pos += Machine._sz;

	const NumberOfSections = loadU2(d, pos);
	pos += NumberOfSections._sz;

	const TimeDateStamp = loadU4(d, pos);
	pos += TimeDateStamp._sz;

	const PointerToSymbolTable = loadU4(d, pos);
	pos += PointerToSymbolTable._sz;

	const NumberOfSymbols = loadU4(d, pos);
	pos += NumberOfSymbols._sz;

	const SizeOfOptionalHeader = loadU2(d, pos);
	pos += SizeOfOptionalHeader._sz;

	const Characteristics = loadE2<PE.FileAttr>(d, pos);
	pos += Characteristics._sz;

	return {
		_off, _sz: pos - _off,
		Machine,
		NumberOfSections,
		TimeDateStamp,
		PointerToSymbolTable,
		NumberOfSymbols,
		SizeOfOptionalHeader,
		Characteristics,
	};
}

function loadOptionalHeader(d: DataView, _off: number): PE.OptionalHeader {
	chk(d, _off, 2);
	const magic = d.getUint16(_off, true);
	switch (magic) {
		case PE.ntOptHdr32Magic: return loadOptionalHeader32(d, _off);
		case PE.ntOptHdr64Magic: return loadOptionalHeader64(d, _off);
		default: throw new E.PeError(E.PeErrorType.InvalidOptionalHeaderMagic, _off, 2, magic);
	}
}

function loadOptionalHeader32(d: DataView, _off: number): PE.OptionalHeader32 {
	let pos = _off;

	//
	// Standard fields.
	//

	const Magic = loadU2(d, pos);
	pos += Magic._sz;

	if (Magic.value != PE.ntOptHdr32Magic)
		err(E.PeErrorType.InvalidOptionalHeaderMagic, Magic);

	const MajorLinkerVersion = loadU1(d, pos);
	pos += MajorLinkerVersion._sz;

	const MinorLinkerVersion = loadU1(d, pos);
	pos += MinorLinkerVersion._sz;

	const SizeOfCode = loadU4(d, pos);
	pos += SizeOfCode._sz;

	const SizeOfInitializedData = loadU4(d, pos);
	pos += SizeOfInitializedData._sz;

	const SizeOfUninitializedData = loadU4(d, pos);
	pos += SizeOfUninitializedData._sz;

	const AddressOfEntryPoint = loadU4(d, pos);
	pos += AddressOfEntryPoint._sz;

	const BaseOfCode = loadU4(d, pos);
	pos += BaseOfCode._sz;

	const BaseOfData = loadU4(d, pos);
	pos += BaseOfData._sz;

	//
	// NT additional fields.
	//

	const ImageBase = loadU4(d, pos);
	pos += ImageBase._sz;

	const SectionAlignment = loadU4(d, pos);
	pos += SectionAlignment._sz;

	const FileAlignment = loadU4(d, pos);
	pos += FileAlignment._sz;

	const MajorOperatingSystemVersion = loadU2(d, pos);
	pos += MajorOperatingSystemVersion._sz;

	const MinorOperatingSystemVersion = loadU2(d, pos);
	pos += MinorOperatingSystemVersion._sz;

	const MajorImageVersion = loadU2(d, pos);
	pos += MajorImageVersion._sz;

	const MinorImageVersion = loadU2(d, pos);
	pos += MinorImageVersion._sz;

	const MajorSubsystemVersion = loadU2(d, pos);
	pos += MajorSubsystemVersion._sz;

	const MinorSubsystemVersion = loadU2(d, pos);
	pos += MinorSubsystemVersion._sz;

	const Win32VersionValue = loadU4(d, pos);
	pos += Win32VersionValue._sz;

	const SizeOfImage = loadU4(d, pos);
	pos += SizeOfImage._sz;

	const SizeOfHeaders = loadU4(d, pos);
	pos += SizeOfHeaders._sz;

	const CheckSum = loadU4(d, pos);
	pos += CheckSum._sz;

	const Subsystem = loadE2<PE.Subsystem>(d, pos);
	pos += Subsystem._sz;

	const DllCharacteristics = loadE2<PE.DllAttr>(d, pos);
	pos += DllCharacteristics._sz;

	const SizeOfStackReserve = loadU4(d, pos);
	pos += SizeOfStackReserve._sz;

	const SizeOfStackCommit = loadU4(d, pos);
	pos += SizeOfStackCommit._sz;

	const SizeOfHeapReserve = loadU4(d, pos);
	pos += SizeOfHeapReserve._sz;

	const SizeOfHeapCommit = loadU4(d, pos);
	pos += SizeOfHeapCommit._sz;

	const LoaderFlags = loadU4(d, pos);
	pos += LoaderFlags._sz;

	const NumberOfRvaAndSizes = loadU4(d, pos);
	pos += NumberOfRvaAndSizes._sz;

	if (NumberOfRvaAndSizes.value != PE.numberOfDataDirectories)
		err(E.PeErrorType.InvalidNumberOfDataDirectories, NumberOfRvaAndSizes);

	const DataDirectories = loadFileDataVecByCount(d, pos, PE.numberOfDataDirectories, loadDataDirectory);
	pos += DataDirectories._sz;

	return {
		_off, _sz: pos - _off,
		//
		// Standard fields.
		//
		Magic,
		MajorLinkerVersion,
		MinorLinkerVersion,
		SizeOfCode,
		SizeOfInitializedData,
		SizeOfUninitializedData,
		AddressOfEntryPoint,
		BaseOfCode,
		BaseOfData,
		//
		// NT additional fields.
		//
		ImageBase,
		SectionAlignment,
		FileAlignment,
		MajorOperatingSystemVersion,
		MinorOperatingSystemVersion,
		MajorImageVersion,
		MinorImageVersion,
		MajorSubsystemVersion,
		MinorSubsystemVersion,
		Win32VersionValue,
		SizeOfImage,
		SizeOfHeaders,
		CheckSum,
		Subsystem,
		DllCharacteristics,
		SizeOfStackReserve,
		SizeOfStackCommit,
		SizeOfHeapReserve,
		SizeOfHeapCommit,
		LoaderFlags,
		NumberOfRvaAndSizes,
		//
		// Data Directories.
		//
		DataDirectories
	};
}

function loadOptionalHeader64(d: DataView, _off: number): PE.OptionalHeader64 {
	let pos = _off;

	//
	// Standard fields.
	//

	const Magic = loadU2(d, pos);
	pos += Magic._sz;

	if (Magic.value != PE.ntOptHdr64Magic)
		err(E.PeErrorType.InvalidOptionalHeaderMagic, Magic);

	const MajorLinkerVersion = loadU1(d, pos);
	pos += MajorLinkerVersion._sz;

	const MinorLinkerVersion = loadU1(d, pos);
	pos += MinorLinkerVersion._sz;

	const SizeOfCode = loadU4(d, pos);
	pos += SizeOfCode._sz;

	const SizeOfInitializedData = loadU4(d, pos);
	pos += SizeOfInitializedData._sz;

	const SizeOfUninitializedData = loadU4(d, pos);
	pos += SizeOfUninitializedData._sz;

	const AddressOfEntryPoint = loadU4(d, pos);
	pos += AddressOfEntryPoint._sz;

	const BaseOfCode = loadU4(d, pos);
	pos += BaseOfCode._sz;

	//
	// NT additional fields.
	//

	const ImageBase = loadU8(d, pos);
	pos += ImageBase._sz;

	const SectionAlignment = loadU4(d, pos);
	pos += SectionAlignment._sz;

	const FileAlignment = loadU4(d, pos);
	pos += FileAlignment._sz;

	const MajorOperatingSystemVersion = loadU2(d, pos);
	pos += MajorOperatingSystemVersion._sz;

	const MinorOperatingSystemVersion = loadU2(d, pos);
	pos += MinorOperatingSystemVersion._sz;

	const MajorImageVersion = loadU2(d, pos);
	pos += MajorImageVersion._sz;

	const MinorImageVersion = loadU2(d, pos);
	pos += MinorImageVersion._sz;

	const MajorSubsystemVersion = loadU2(d, pos);
	pos += MajorSubsystemVersion._sz;

	const MinorSubsystemVersion = loadU2(d, pos);
	pos += MinorSubsystemVersion._sz;

	const Win32VersionValue = loadU4(d, pos);
	pos += Win32VersionValue._sz;

	const SizeOfImage = loadU4(d, pos);
	pos += SizeOfImage._sz;

	const SizeOfHeaders = loadU4(d, pos);
	pos += SizeOfHeaders._sz;

	const CheckSum = loadU4(d, pos);
	pos += CheckSum._sz;

	const Subsystem = loadU2(d, pos);
	pos += Subsystem._sz;

	const DllCharacteristics = loadU2(d, pos);
	pos += DllCharacteristics._sz;

	const SizeOfStackReserve = loadU8(d, pos);
	pos += SizeOfStackReserve._sz;

	const SizeOfStackCommit = loadU8(d, pos);
	pos += SizeOfStackCommit._sz;

	const SizeOfHeapReserve = loadU8(d, pos);
	pos += SizeOfHeapReserve._sz;

	const SizeOfHeapCommit = loadU8(d, pos);
	pos += SizeOfHeapCommit._sz;

	const LoaderFlags = loadU4(d, pos);
	pos += LoaderFlags._sz;

	const NumberOfRvaAndSizes = loadU4(d, pos);
	pos += NumberOfRvaAndSizes._sz;

	if (NumberOfRvaAndSizes.value != PE.numberOfDataDirectories)
		err(E.PeErrorType.InvalidNumberOfDataDirectories, NumberOfRvaAndSizes);

	const DataDirectories = loadFileDataVecByCount(d, pos, PE.numberOfDataDirectories, loadDataDirectory);
	pos += DataDirectories._sz;

	return {
		_off, _sz: pos - _off,
		//
		// Standard fields.
		//
		Magic,
		MajorLinkerVersion,
		MinorLinkerVersion,
		SizeOfCode,
		SizeOfInitializedData,
		SizeOfUninitializedData,
		AddressOfEntryPoint,
		BaseOfCode,
		//
		// NT additional fields.
		//
		ImageBase,
		SectionAlignment,
		FileAlignment,
		MajorOperatingSystemVersion,
		MinorOperatingSystemVersion,
		MajorImageVersion,
		MinorImageVersion,
		MajorSubsystemVersion,
		MinorSubsystemVersion,
		Win32VersionValue,
		SizeOfImage,
		SizeOfHeaders,
		CheckSum,
		Subsystem,
		DllCharacteristics,
		SizeOfStackReserve,
		SizeOfStackCommit,
		SizeOfHeapReserve,
		SizeOfHeapCommit,
		LoaderFlags,
		NumberOfRvaAndSizes,
		//
		// Data Directories.
		//
		DataDirectories
	};
}

function loadDataDirectory(d: DataView, _off: number): PE.DataDirectory {
	let pos = _off;

	const Rva = loadU4(d, pos);
	pos += Rva._sz;

	const Size = loadU4(d, pos);
	pos += Size._sz;

	return {
		_off, _sz: pos - _off,
		Rva,
		Size,
	};
}

function loadSectionHeader(d: DataView, _off: number): PE.SectionHeader {
	let pos = _off;

	const Name = loadFixedSizeAsciiString(d, pos, 8);
	pos += Name._sz;

	const VirtualSize = loadU4(d, pos);
	pos += VirtualSize._sz;

	const VirtualAddress = loadU4(d, pos);
	pos += VirtualAddress._sz;

	const SizeOfRawData = loadU4(d, pos);
	pos += SizeOfRawData._sz;

	const PointerToRawData = loadU4(d, pos);
	pos += PointerToRawData._sz;

	const PointerToRelocations = loadU4(d, pos);
	pos += PointerToRelocations._sz;

	const PointerToLinenumbers = loadU4(d, pos);
	pos += PointerToLinenumbers._sz;

	const NumberOfRelocations = loadU2(d, pos);
	pos += NumberOfRelocations._sz;

	const NumberOfLinenumbers = loadU2(d, pos);
	pos += NumberOfLinenumbers._sz;

	const Characteristics = loadE4<PE.SectionAttr>(d, pos);
	pos += Characteristics._sz;

	return {
		_off, _sz: pos - _off,
		Name,
		VirtualSize,
		VirtualAddress,
		SizeOfRawData,
		PointerToRawData,
		PointerToRelocations,
		PointerToLinenumbers,
		NumberOfRelocations,
		NumberOfLinenumbers,
		Characteristics,
	};
}

function loadSectionHeaders(d: DataView, _off: number, count: number): PE.FileDataVec<PE.SectionHeader> {
	return loadFileDataVecByCount(d, _off, count, loadSectionHeader);
}

//-----------------------------------------------------------------------------------------------------------------
// Metadata.
//-----------------------------------------------------------------------------------------------------------------

function loadMetadata(pe: PE.PeStruct) {
	let pos: number;

	const dd = pe.optionalHeader.DataDirectories.values[PE.DataDirectoryIndex.ComDescriptor];
	pos = U.rvaToOffset(pe, dd.Rva.value);
	const cliHeader = loadCliHeader(pe.data, pos);

	let ManRes: PE.FileDataVec<PE.ManResItem>;
	const ddmr = cliHeader.Resources;
	if (ddmr.Rva.value > 0 && ddmr.Size.value > 0) {
		pos = U.rvaToOffset(pe, ddmr.Rva.value);
		const end = pos + ddmr.Size.value;
		ManRes = loadFileDataVecByStop(pe.data, pos, (i) => i._off + i._sz >= end, loadManResItem);
	}

	let SNSignature: PE.FileData;
	const ddsn = cliHeader.StrongNameSignature;
	if (ddsn.Rva.value > 0 && ddsn.Size.value > 0) {
		pos = U.rvaToOffset(pe, ddsn.Rva.value);
		SNSignature = loadFileData(pe.data, pos, ddsn.Size.value);
	}

	pos = U.rvaToOffset(pe, cliHeader.MetaData.Rva.value);
	const mdRoot = loadMdRoot(pe.data, pos);

	let mdsStrings: PE.FileDataVec<PE.NullTerminatedUtf8StringField> = null;
	let mdsUS: PE.FileDataVec<PE.MdsUsItem> = null;
	let mdsGuid: PE.FileDataVec<PE.FileData> = null;
	let mdsBlob: PE.FileDataVec<PE.MdsBlobItem> = null;
	let mdsTable: any = null;

	const mdOffset = U.rvaToOffset(pe, cliHeader.MetaData.Rva.value);
	for (let sh of mdRoot.StreamHeaders.values) {
		let pos = mdOffset + sh.Offset.value;
		switch (sh.Name.value) {
			case PE.mdsNameStrings:
				mdsStrings = loadMdsStrings(pe.data, sh, pos);
				break;
			case PE.mdsNameUS:
				mdsUS = loadMdsUS(pe.data, sh, pos);
				break;
			case PE.mdsNameGuid:
				mdsGuid = loadMdsGuid(pe.data, sh, pos);
				break;
			case PE.mdsNameBlob:
				mdsBlob = loadMdsBlob(pe.data, sh, pos);
				break;
			case PE.mdsNameTable:
				mdsTable = loadMdTables(pe.data, pos);
				break;
		}
	}

	return Object.assign({
		cliHeader,
		ManRes,
		SNSignature,
		mdRoot,
		mdsStrings,
		mdsUS,
		mdsGuid,
		mdsBlob,
	}, mdsTable);
}

function loadCliHeader(d: DataView, _off: number): PE.CliHeader {
	let pos = _off;

	const cb = loadU4(d, pos);
	pos += cb._sz;

	const MajorRuntimeVersion = loadU2(d, pos);
	pos += MajorRuntimeVersion._sz;

	const MinorRuntimeVersion = loadU2(d, pos);
	pos += MinorRuntimeVersion._sz;

	const MetaData = loadDataDirectory(d, pos);
	pos += MetaData._sz;

	const Flags = loadE4<PE.ComImageAttr>(d, pos);
	pos += Flags._sz;

	const EntryPointToken = loadU4(d, pos);
	pos += EntryPointToken._sz;

	const Resources = loadDataDirectory(d, pos);
	pos += Resources._sz;

	const StrongNameSignature = loadDataDirectory(d, pos);
	pos += StrongNameSignature._sz;

	const CodeManagerTable = loadDataDirectory(d, pos);
	pos += CodeManagerTable._sz;

	const VTableFixups = loadDataDirectory(d, pos);
	pos += VTableFixups._sz;

	const ExportAddressTableJumps = loadDataDirectory(d, pos);
	pos += ExportAddressTableJumps._sz;

	const ManagedNativeHeader = loadDataDirectory(d, pos);
	pos += ManagedNativeHeader._sz;

	if (pos - _off != cb.value)
		err(E.PeErrorType.InvalidSizeOfCliHeader, cb);

	return {
		_off, _sz: pos - _off,
		cb,
		MajorRuntimeVersion,
		MinorRuntimeVersion,
		MetaData,
		Flags,
		EntryPointToken,
		Resources,
		StrongNameSignature,
		CodeManagerTable,
		VTableFixups,
		ExportAddressTableJumps,
		ManagedNativeHeader,
	};
}

function loadManResItem(d: DataView, _off: number): PE.ManResItem {
	let pos = _off;

	const Size = loadU4(d, pos);
	pos += Size._sz;

	const Data = loadFileData(d, pos, Size.value);
	pos += Data._sz;

	const Padding = loadFileData(d, pos, calculatePaddingSize(Data._sz));
	pos += Padding._sz;

	return {
		_off, _sz: pos - _off,
		Size,
		Data,
		Padding,
	};
}

function loadMdRoot(d: DataView, _off: number): PE.MdRoot {
	let pos = _off;

	const Signature = loadU4(d, pos);
	pos += Signature._sz;

	if (Signature.value != PE.mdSignature)
		err(E.PeErrorType.InvalidMdSignature, Signature);

	const MajorVersion = loadU2(d, pos);
	pos += MajorVersion._sz;

	const MinorVersion = loadU2(d, pos);
	pos += MinorVersion._sz;

	const Reserved = loadU4(d, pos);
	pos += Reserved._sz;

	const VersionLength = loadU4(d, pos);
	pos += VersionLength._sz;

	const Version = loadNullTerminatedUtf8String(d, pos);
	pos += Version._sz;

	const VersionPadding = loadFileData(d, pos, calculatePaddingSize(Version._sz));
	pos += VersionPadding._sz;

	const Flags = loadU2(d, pos);
	pos += Flags._sz;

	const NumberOfStreams = loadU2(d, pos);
	pos += NumberOfStreams._sz;

	const StreamHeaders = loadFileDataVecByCount(d, pos, NumberOfStreams.value, loadMdStreamHeader);
	pos += StreamHeaders._sz;

	return {
		_off, _sz: pos - _off,
		Signature,
		MajorVersion,
		MinorVersion,
		Reserved,
		VersionLength,
		Version,
		VersionPadding,
		Flags,
		NumberOfStreams,
		StreamHeaders,
	};
}

function loadMdStreamHeader(d: DataView, _off: number): PE.MdStreamHeader {
	let pos = _off;

	const Offset = loadU4(d, pos);
	pos += Offset._sz;

	const Size = loadU4(d, pos);
	pos += Size._sz;

	const Name = loadNullTerminatedAsciiString(d, pos);
	pos += Name._sz;

	const Padding = loadFileData(d, pos, calculatePaddingSize(Name._sz));
	pos += Padding._sz;

	return {
		_off, _sz: pos - _off,
		Offset,
		Size,
		Name,
		Padding,
	};
}

function loadMdsStrings(d: DataView, sh: PE.MdStreamHeader, _off: number)
	: PE.FileDataVec<PE.NullTerminatedUtf8StringField> {
	const end = _off + sh.Size.value;
	return loadFileDataVecByStop(d, _off, (i) => (i._off + i._sz) >= end,
		loadNullTerminatedUtf8String);
}

function loadMdsUS(d: DataView, sh: PE.MdStreamHeader, _off: number)
	: PE.FileDataVec<PE.MdsUsItem> {
	const end = _off + sh.Size.value;
	return loadFileDataVecByStop(d, _off, (i) => (i._off + i._sz) >= end, loadMdsUsItem);
}

function loadMdsUsItem(d: DataView, _off: number): PE.MdsUsItem {
	let pos = _off;

	const compressedSize = loadCompressedUint(d, pos);
	pos += compressedSize._sz;

	let strSize = 0, suffixLen = 0;
	if (compressedSize.value > 0) {
		strSize = compressedSize.value - 1;
		suffixLen = 1;
	}

	const userString = loadFixedSizeUnicodeString(d, pos, strSize);
	pos += userString._sz;

	const suffix = loadFileData(d, pos, suffixLen);
	pos += suffix._sz;

	return {
		_off, _sz: pos - _off,
		compressedSize,
		userString,
		suffix,
	};
}

function loadMdsGuid(d: DataView, sh: PE.MdStreamHeader, _off: number)
	: PE.FileDataVec<PE.FileData> {
	const end = _off + sh.Size.value;
	return loadFileDataVecByStop(d, _off, (i) => (i._off + i._sz) >= end,
		(d, o) => loadFileData(d, o, 16));
}

function loadMdsBlob(d: DataView, sh: PE.MdStreamHeader, _off: number)
	: PE.FileDataVec<PE.MdsBlobItem> {
	const end = _off + sh.Size.value;
	return loadFileDataVecByStop(d, _off,
		(i) => (i._off + i._sz) >= end, loadMdsBlobItem);
}

function loadMdsBlobItem(d: DataView, _off: number): PE.MdsBlobItem {
	let pos = _off;

	const compressedSize = loadCompressedUint(d, pos);
	pos += compressedSize._sz;

	const data = loadFileData(d, pos, compressedSize.value);
	pos += data._sz;

	return {
		_off, _sz: pos - _off,
		compressedSize,
		data,
	};
}

function loadMdTables(d: DataView, _off: number) {
	let pos = _off;

	const mdTableHeader = loadMdTableHeader(d, pos);
	pos += mdTableHeader._sz;

	const mdTableRows = calMdTableRows(mdTableHeader);
	const ctx = getMdtLoadingContext(mdTableHeader, mdTableRows);

	let mdtModule = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Module],
		(d, o) => loadMdtModule(d, o, ctx));
	pos += mdtModule._sz

	let mdtTypeRef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.TypeRef],
		(d, o) => loadMdtTypeRef(d, o, ctx));
	pos += mdtTypeRef._sz

	let mdtTypeDef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.TypeDef],
		(d, o) => loadMdtTypeDef(d, o, ctx));
	pos += mdtTypeDef._sz

	let mdtFieldPtr = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.FieldPtr],
		(d, o) => loadMdtFieldPtr(d, o, ctx));
	pos += mdtFieldPtr._sz

	let mdtField = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Field],
		(d, o) => loadMdtField(d, o, ctx));
	pos += mdtField._sz

	let mdtMethodPtr = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MethodPtr],
		(d, o) => loadMdtMethodPtr(d, o, ctx));
	pos += mdtMethodPtr._sz

	let mdtMethodDef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MethodDef],
		(d, o) => loadMdtMethodDef(d, o, ctx));
	pos += mdtMethodDef._sz

	let mdtParamPtr = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ParamPtr],
		(d, o) => loadMdtParamPtr(d, o, ctx));
	pos += mdtParamPtr._sz

	let mdtParam = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Param],
		(d, o) => loadMdtParam(d, o, ctx));
	pos += mdtParam._sz

	let mdtInterfaceImpl = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.InterfaceImpl],
		(d, o) => loadMdtInterfaceImpl(d, o, ctx));
	pos += mdtInterfaceImpl._sz

	let mdtMemberRef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MemberRef],
		(d, o) => loadMdtMemberRef(d, o, ctx));
	pos += mdtMemberRef._sz

	let mdtConstant = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Constant],
		(d, o) => loadMdtConstant(d, o, ctx));
	pos += mdtConstant._sz

	let mdtCustomAttribute = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.CustomAttribute],
		(d, o) => loadMdtCustomAttribute(d, o, ctx));
	pos += mdtCustomAttribute._sz

	let mdtFieldMarshal = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.FieldMarshal],
		(d, o) => loadMdtFieldMarshal(d, o, ctx));
	pos += mdtFieldMarshal._sz

	let mdtDeclSecurity = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.DeclSecurity],
		(d, o) => loadMdtDeclSecurity(d, o, ctx));
	pos += mdtDeclSecurity._sz

	let mdtClassLayout = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ClassLayout],
		(d, o) => loadMdtClassLayout(d, o, ctx));
	pos += mdtClassLayout._sz

	let mdtFieldLayout = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.FieldLayout],
		(d, o) => loadMdtFieldLayout(d, o, ctx));
	pos += mdtFieldLayout._sz

	let mdtStandAloneSig = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.StandAloneSig],
		(d, o) => loadMdtStandAloneSig(d, o, ctx));
	pos += mdtStandAloneSig._sz

	let mdtEventMap = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.EventMap],
		(d, o) => loadMdtEventMap(d, o, ctx));
	pos += mdtEventMap._sz

	let mdtEventPtr = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.EventPtr],
		(d, o) => loadMdtEventPtr(d, o, ctx));
	pos += mdtEventPtr._sz

	let mdtEvent = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Event],
		(d, o) => loadMdtEvent(d, o, ctx));
	pos += mdtEvent._sz

	let mdtPropertyMap = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.PropertyMap],
		(d, o) => loadMdtPropertyMap(d, o, ctx));
	pos += mdtPropertyMap._sz

	let mdtPropertyPtr = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.PropertyPtr],
		(d, o) => loadMdtPropertyPtr(d, o, ctx));
	pos += mdtPropertyPtr._sz

	let mdtProperty = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Property],
		(d, o) => loadMdtProperty(d, o, ctx));
	pos += mdtProperty._sz

	let mdtMethodSemantics = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MethodSemantics],
		(d, o) => loadMdtMethodSemantics(d, o, ctx));
	pos += mdtMethodSemantics._sz

	let mdtMethodImpl = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MethodImpl],
		(d, o) => loadMdtMethodImpl(d, o, ctx));
	pos += mdtMethodImpl._sz

	let mdtModuleRef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ModuleRef],
		(d, o) => loadMdtModuleRef(d, o, ctx));
	pos += mdtModuleRef._sz

	let mdtTypeSpec = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.TypeSpec],
		(d, o) => loadMdtTypeSpec(d, o, ctx));
	pos += mdtTypeSpec._sz

	let mdtImplMap = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ImplMap],
		(d, o) => loadMdtImplMap(d, o, ctx));
	pos += mdtImplMap._sz

	let mdtFieldRVA = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.FieldRVA],
		(d, o) => loadMdtFieldRVA(d, o, ctx));
	pos += mdtFieldRVA._sz

	let mdtENCLog = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ENCLog],
		(d, o) => loadMdtENCLog(d, o, ctx));
	pos += mdtENCLog._sz

	let mdtENCMap = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ENCMap],
		(d, o) => loadMdtENCMap(d, o, ctx));
	pos += mdtENCMap._sz

	let mdtAssembly = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.Assembly],
		(d, o) => loadMdtAssembly(d, o, ctx));
	pos += mdtAssembly._sz

	let mdtAssemblyProcessor = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.AssemblyProcessor],
		(d, o) => loadMdtAssemblyProcessor(d, o, ctx));
	pos += mdtAssemblyProcessor._sz

	let mdtAssemblyOS = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.AssemblyOS],
		(d, o) => loadMdtAssemblyOS(d, o, ctx));
	pos += mdtAssemblyOS._sz

	let mdtAssemblyRef = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.AssemblyRef],
		(d, o) => loadMdtAssemblyRef(d, o, ctx));
	pos += mdtAssemblyRef._sz

	let mdtAssemblyRefProcessor = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.AssemblyRefProcessor],
		(d, o) => loadMdtAssemblyRefProcessor(d, o, ctx));
	pos += mdtAssemblyRefProcessor._sz

	let mdtAssemblyRefOS = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.AssemblyRefOS],
		(d, o) => loadMdtAssemblyRefOS(d, o, ctx));
	pos += mdtAssemblyRefOS._sz

	let mdtFile = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.File],
		(d, o) => loadMdtFile(d, o, ctx));
	pos += mdtFile._sz

	let mdtExportedType = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ExportedType],
		(d, o) => loadMdtExportedType(d, o, ctx));
	pos += mdtExportedType._sz

	let mdtManifestResource = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.ManifestResource],
		(d, o) => loadMdtManifestResource(d, o, ctx));
	pos += mdtManifestResource._sz

	let mdtNestedClass = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.NestedClass],
		(d, o) => loadMdtNestedClass(d, o, ctx));
	pos += mdtNestedClass._sz

	let mdtGenericParam = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.GenericParam],
		(d, o) => loadMdtGenericParam(d, o, ctx));
	pos += mdtGenericParam._sz

	let mdtMethodSpec = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.MethodSpec],
		(d, o) => loadMdtMethodSpec(d, o, ctx));
	pos += mdtMethodSpec._sz

	let mdtGenericParamConstraint = loadFileDataVecByCount(d, pos,
		mdTableRows[PE.MdTableIndex.GenericParamConstraint],
		(d, o) => loadMdtGenericParamConstraint(d, o, ctx));
	pos += mdtGenericParamConstraint._sz

	return {
		mdTableHeader,
		mdTableRows,

		mdtModule,
		mdtTypeRef,
		mdtTypeDef,
		mdtFieldPtr,
		mdtField,
		mdtMethodPtr,
		mdtMethodDef,
		mdtParamPtr,
		mdtParam,
		mdtInterfaceImpl,
		mdtMemberRef,
		mdtConstant,
		mdtCustomAttribute,
		mdtFieldMarshal,
		mdtDeclSecurity,
		mdtClassLayout,
		mdtFieldLayout,
		mdtStandAloneSig,
		mdtEventMap,
		mdtEventPtr,
		mdtEvent,
		mdtPropertyMap,
		mdtPropertyPtr,
		mdtProperty,
		mdtMethodSemantics,
		mdtMethodImpl,
		mdtModuleRef,
		mdtTypeSpec,
		mdtImplMap,
		mdtFieldRVA,
		mdtENCLog,
		mdtENCMap,
		mdtAssembly,
		mdtAssemblyProcessor,
		mdtAssemblyOS,
		mdtAssemblyRef,
		mdtAssemblyRefProcessor,
		mdtAssemblyRefOS,
		mdtFile,
		mdtExportedType,
		mdtManifestResource,
		mdtNestedClass,
		mdtGenericParam,
		mdtMethodSpec,
		mdtGenericParamConstraint,
	};
}

function loadMdTableHeader(d: DataView, _off: number): PE.MdTableHeader {
	let pos = _off;

	const Reserved = loadU4(d, pos);
	pos += Reserved._sz;

	const MajorVersion = loadU1(d, pos);
	pos += MajorVersion._sz;

	const MinorVersion = loadU1(d, pos);
	pos += MinorVersion._sz;

	const HeapSizes = loadE1<PE.MdHeapSizeAttr>(d, pos);
	pos += HeapSizes._sz;

	const Reserved2 = loadU1(d, pos);
	pos += Reserved2._sz;

	const Valid = loadU8(d, pos);
	pos += Valid._sz;

	const Sorted = loadU8(d, pos);
	pos += Sorted._sz;

	const rowCount = count1(Valid.high) + count1(Valid.low)
	const Rows = loadFileDataVecByCount(d, pos, rowCount, loadU4);
	pos += Rows._sz;

	return {
		_off, _sz: pos - _off,
		Reserved,
		MajorVersion,
		MinorVersion,
		HeapSizes,
		Reserved2,
		Valid,
		Sorted,
		Rows,
	};
}

function calMdTableRows(h: PE.MdTableHeader): number[] {
	let rows = new Array<number>(PE.numberOfMdTables);
	let p = 0;
	for (let i = 0; i < PE.numberOfMdTables; i++) {
		let mask: number, valid: number;
		if (i < 32) {
			mask = 1 << i; valid = h.Valid.low;
		} else {
			mask = 1 << (i - 32); valid = h.Valid.high;
		}

		rows[i] = (mask & valid) ? h.Rows.values[p++].value : 0;
	}
	return rows;
}

enum MdCodedTokenIndex {
	TypeDefOrRef = 0,
	HasConstant = 1,
	HasCustomAttribute = 2,
	HasFieldMarshall = 3,
	HasDeclSecurity = 4,
	MemberRefParent = 5,
	HasSemantics = 6,
	MethodDefOrRef = 7,
	MemberForwarded = 8,
	Implementation = 9,
	CustomAttributeType = 10,
	ResolutionScope = 11,
	TypeOrMethodDef = 12,
}

const numberOfMdCodedTokens = 13;

interface MdCodedTokenInfo {
	tagSize: number;
	tables: PE.MdTableIndex[];
}

const ctc: MdCodedTokenInfo[] = [{
	tagSize: 2, tables: [  // TypeDefOrRef
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.TypeRef,
		PE.MdTableIndex.TypeSpec,
	]
}, {
	tagSize: 2, tables: [  // HasConstant
		PE.MdTableIndex.Field,
		PE.MdTableIndex.Param,
		PE.MdTableIndex.Property,
	]
}, {
	tagSize: 5, tables: [  // HasCustomAttribute
		PE.MdTableIndex.MethodDef,
		PE.MdTableIndex.Field,
		PE.MdTableIndex.TypeRef,
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.Param,
		PE.MdTableIndex.InterfaceImpl,
		PE.MdTableIndex.MemberRef,
		PE.MdTableIndex.Module,
		PE.MdTableIndex.DeclSecurity,
		PE.MdTableIndex.Property,
		PE.MdTableIndex.Event,
		PE.MdTableIndex.StandAloneSig,
		PE.MdTableIndex.ModuleRef,
		PE.MdTableIndex.TypeSpec,
		PE.MdTableIndex.Assembly,
		PE.MdTableIndex.AssemblyRef,
		PE.MdTableIndex.File,
		PE.MdTableIndex.ExportedType,
		PE.MdTableIndex.ManifestResource,
		PE.MdTableIndex.GenericParam,
		PE.MdTableIndex.GenericParamConstraint,
		PE.MdTableIndex.MethodSpec,
	]
}, {
	tagSize: 1, tables: [  // HasFieldMarshall
		PE.MdTableIndex.Field,
		PE.MdTableIndex.Param,
	]
}, {
	tagSize: 2, tables: [  // HasDeclSecurity
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.MethodDef,
		PE.MdTableIndex.Assembly,
	]
}, {
	tagSize: 3, tables: [  // MemberRefParent
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.TypeRef,
		PE.MdTableIndex.ModuleRef,
		PE.MdTableIndex.MethodDef,
		PE.MdTableIndex.TypeSpec,
	]
}, {
	tagSize: 1, tables: [  // HasSemantics
		PE.MdTableIndex.Event,
		PE.MdTableIndex.Property,
	]
}, {
	tagSize: 1, tables: [  // MethodDefOrRef
		PE.MdTableIndex.MethodDef,
		PE.MdTableIndex.MemberRef,
	]
}, {
	tagSize: 1, tables: [  // MemberForwarded
		PE.MdTableIndex.Field,
		PE.MdTableIndex.MethodDef,
	]
}, {
	tagSize: 2, tables: [  // Implementation
		PE.MdTableIndex.File,
		PE.MdTableIndex.AssemblyRef,
		PE.MdTableIndex.ExportedType,
	]
}, {
	tagSize: 3, tables: [  // CustomAttributeType
		PE.MdTableIndex.TypeRef,
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.MethodDef,
		PE.MdTableIndex.MemberRef,
		PE.MdTableIndex.String,
	]
}, {
	tagSize: 2, tables: [  // ResolutionScope
		PE.MdTableIndex.Module,
		PE.MdTableIndex.ModuleRef,
		PE.MdTableIndex.AssemblyRef,
		PE.MdTableIndex.TypeRef,
	]
}, {
	tagSize: 1, tables: [  // TypeOrMethodDef
		PE.MdTableIndex.TypeDef,
		PE.MdTableIndex.MethodDef,
	]
}]

// Metadata table loading context.
interface MdtLoadingContext {
	loadStrings: (d: DataView, o: number) => PE.MdsStringsField;
	loadGuid: (d: DataView, o: number) => PE.MdsGuidField;
	laodBlob: (d: DataView, o: number) => PE.MdsBlobField;
	loadRid: ((d: DataView, o: number) => PE.MdtRidField)[];
	loadCodedToken: ((d: DataView, o: number) => PE.MdCodedTokenField)[];
}

function getMdtLoadingContext(h: PE.MdTableHeader, rows: number[]): MdtLoadingContext {
	const hs = h.HeapSizes.value;
	return {
		loadStrings: (hs & PE.MdHeapSizeAttr.Strings) != 0 ? loadU4 : loadU2,
		loadGuid: (hs & PE.MdHeapSizeAttr.Guid) != 0 ? loadU4 : loadU2,
		laodBlob: (hs & PE.MdHeapSizeAttr.Blob) != 0 ? loadU4 : loadU2,
		loadRid: rows.map(r => r > 0xFFFF ? loadU4 : loadU2),
		loadCodedToken: ctc.map((c) => {
			const maxRows = 0xFFFF >> c.tagSize;
			for (let tid of c.tables) {
				if (rows[tid] > maxRows) {
					return (d: DataView, o: number) => loadMdCodedToken4(d, o, c);
				}
			}
			return (d: DataView, o: number) => loadMdCodedToken2(d, o, c);
		})
	};
}

function loadMdtModule(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtModuleItem {
	let pos = _off;

	const Generation = loadU2(d, pos);
	pos += Generation._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Mvid = ctx.loadGuid(d, pos);
	pos += Mvid._sz;

	const EncId = ctx.loadGuid(d, pos);
	pos += EncId._sz;

	const EncBaseId = ctx.loadGuid(d, pos);
	pos += EncBaseId._sz;

	return {
		_off, _sz: pos - _off,
		Generation,
		Name,
		Mvid,
		EncId,
		EncBaseId,
	};
}

function loadMdtTypeRef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtTypeRefItem {
	let pos = _off;

	const ResolutionScope = ctx.loadCodedToken[MdCodedTokenIndex.ResolutionScope](d, pos);
	pos += ResolutionScope._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Namespace = ctx.loadStrings(d, pos);
	pos += Namespace._sz;

	return {
		_off, _sz: pos - _off,
		ResolutionScope,
		Name,
		Namespace,
	};
}

function loadMdtTypeDef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtTypeDefItem {
	let pos = _off;

	const Flags = loadE4<PE.CorTypeAttr>(d, pos);
	pos += Flags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Namespace = ctx.loadStrings(d, pos);
	pos += Namespace._sz;

	const Extends = ctx.loadCodedToken[MdCodedTokenIndex.TypeDefOrRef](d, pos);
	pos += Extends._sz;

	const FieldList = ctx.loadRid[PE.MdTableIndex.Field](d, pos);
	pos += FieldList._sz;

	const MethodList = ctx.loadRid[PE.MdTableIndex.MethodDef](d, pos);
	pos += MethodList._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		Name,
		Namespace,
		Extends,
		FieldList,
		MethodList,
	};
}

function loadMdtFieldPtr(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFieldPtrItem {
	let pos = _off;

	const Field = ctx.loadRid[PE.MdTableIndex.Field](d, pos);
	pos += Field._sz;

	return {
		_off, _sz: pos - _off,
		Field,
	};
}

function loadMdtField(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFieldItem {
	let pos = _off;

	const Flags = loadE2<PE.CorFieldAttr>(d, pos);
	pos += Flags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Signature = ctx.laodBlob(d, pos);
	pos += Signature._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		Name,
		Signature,
	};
}

function loadMdtMethodPtr(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMethodPtrItem {
	let pos = _off;

	const Method = ctx.loadRid[PE.MdTableIndex.MethodDef](d, pos);
	pos += Method._sz;

	return {
		_off, _sz: pos - _off,
		Method,
	};
}

function loadMdtMethodDef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMethodDefItem {
	let pos = _off;

	const RVA = loadU4(d, pos);
	pos += RVA._sz;

	const ImplFlags = loadE2<PE.CorMethodImpl>(d, pos);
	pos += ImplFlags._sz;

	const Flags = loadE2<PE.CorMethodAttr>(d, pos);
	pos += Flags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Signature = ctx.laodBlob(d, pos);
	pos += Signature._sz;

	const ParamList = ctx.loadRid[PE.MdTableIndex.Param](d, pos);
	pos += ParamList._sz;

	return {
		_off, _sz: pos - _off,
		RVA,
		ImplFlags,
		Flags,
		Name,
		Signature,
		ParamList,
	};
}

function loadMdtParamPtr(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtParamPtrItem {
	let pos = _off;

	const Param = ctx.loadRid[PE.MdTableIndex.Param](d, pos);
	pos += Param._sz;

	return {
		_off, _sz: pos - _off,
		Param,
	};
}

function loadMdtParam(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtParamItem {
	let pos = _off;

	const Flags = loadE2<PE.CorParamAttr>(d, pos);
	pos += Flags._sz;

	const Sequence = loadU2(d, pos);
	pos += Sequence._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		Sequence,
		Name,
	};
}

function loadMdtInterfaceImpl(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtInterfaceImplItem {
	let pos = _off;

	const Class = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += Class._sz;

	const Interface = ctx.loadCodedToken[MdCodedTokenIndex.TypeDefOrRef](d, pos);
	pos += Interface._sz;

	return {
		_off, _sz: pos - _off,
		Class,
		Interface,
	};
}

function loadMdtMemberRef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMemberRefItem {
	let pos = _off;

	const Class = ctx.loadCodedToken[MdCodedTokenIndex.MemberRefParent](d, pos);
	pos += Class._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Signature = ctx.laodBlob(d, pos);
	pos += Signature._sz;

	return {
		_off, _sz: pos - _off,
		Class,
		Name,
		Signature,
	};
}

function loadMdtConstant(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtConstantItem {
	let pos = _off;

	const Type = loadE1<PE.CorElementType>(d, pos);
	pos += Type._sz;

	const PaddingZero = loadU1(d, pos);
	pos += PaddingZero._sz;

	const Parent = ctx.loadCodedToken[MdCodedTokenIndex.HasConstant](d, pos);
	pos += Parent._sz;

	const Value = ctx.laodBlob(d, pos);
	pos += Value._sz;

	return {
		_off, _sz: pos - _off,
		Type,
		PaddingZero,
		Parent,
		Value,
	};
}

function loadMdtCustomAttribute(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtCustomAttributeItem {
	let pos = _off;

	const Parent = ctx.loadCodedToken[MdCodedTokenIndex.HasCustomAttribute](d, pos);
	pos += Parent._sz;

	const Type = ctx.loadCodedToken[MdCodedTokenIndex.CustomAttributeType](d, pos);
	pos += Type._sz;

	const Value = ctx.laodBlob(d, pos);
	pos += Value._sz;

	return {
		_off, _sz: pos - _off,
		Parent,
		Type,
		Value,
	};
}

function loadMdtFieldMarshal(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFieldMarshalItem {
	let pos = _off;

	const Parent = ctx.loadCodedToken[MdCodedTokenIndex.HasFieldMarshall](d, pos);
	pos += Parent._sz;

	const NativeType = ctx.laodBlob(d, pos);
	pos += NativeType._sz;

	return {
		_off, _sz: pos - _off,
		Parent,
		NativeType,
	};
}

function loadMdtDeclSecurity(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtDeclSecurityItem {
	let pos = _off;

	const Action = loadE2<PE.CorDeclSecurity>(d, pos);
	pos += Action._sz;

	const Parent = ctx.loadCodedToken[MdCodedTokenIndex.HasDeclSecurity](d, pos);
	pos += Parent._sz;

	const PermissionSet = ctx.laodBlob(d, pos);
	pos += PermissionSet._sz;

	return {
		_off, _sz: pos - _off,
		Action,
		Parent,
		PermissionSet,
	};
}

function loadMdtClassLayout(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtClassLayoutItem {
	let pos = _off;

	const PackingSize = loadU2(d, pos);
	pos += PackingSize._sz;

	const ClassSize = loadU4(d, pos);
	pos += ClassSize._sz;

	const Parent = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += Parent._sz;

	return {
		_off, _sz: pos - _off,
		PackingSize,
		ClassSize,
		Parent,
	};
}

function loadMdtFieldLayout(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFieldLayoutItem {
	let pos = _off;

	const OffSet = loadU4(d, pos);
	pos += OffSet._sz;

	const Field = ctx.loadRid[PE.MdTableIndex.Field](d, pos);
	pos += Field._sz;

	return {
		_off, _sz: pos - _off,
		OffSet,
		Field,
	};
}

function loadMdtStandAloneSig(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtStandAloneSigItem {
	let pos = _off;

	const Signature = ctx.laodBlob(d, pos);
	pos += Signature._sz;

	return {
		_off, _sz: pos - _off,
		Signature,
	};
}

function loadMdtEventMap(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtEventMapItem {
	let pos = _off;

	const Parent = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += Parent._sz;

	const EventList = ctx.loadRid[PE.MdTableIndex.Event](d, pos);
	pos += EventList._sz;

	return {
		_off, _sz: pos - _off,
		Parent,
		EventList,
	};
}

function loadMdtEventPtr(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtEventPtrItem {
	let pos = _off;

	const Event = ctx.loadRid[PE.MdTableIndex.Event](d, pos);
	pos += Event._sz;

	return {
		_off, _sz: pos - _off,
		Event,
	};
}

function loadMdtEvent(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtEventItem {
	let pos = _off;

	const EventFlags = loadE2<PE.CorEventAttr>(d, pos);
	pos += EventFlags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const EventType = ctx.loadCodedToken[MdCodedTokenIndex.TypeDefOrRef](d, pos);
	pos += EventType._sz;

	return {
		_off, _sz: pos - _off,
		EventFlags,
		Name,
		EventType,
	};
}

function loadMdtPropertyMap(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtPropertyMapItem {
	let pos = _off;

	const Parent = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += Parent._sz;

	const PropertyList = ctx.loadRid[PE.MdTableIndex.Property](d, pos);
	pos += PropertyList._sz;

	return {
		_off, _sz: pos - _off,
		Parent,
		PropertyList,
	};
}

function loadMdtPropertyPtr(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtPropertyPtrItem {
	let pos = _off;

	const Property = ctx.loadRid[PE.MdTableIndex.Property](d, pos);
	pos += Property._sz;

	return {
		_off, _sz: pos - _off,
		Property,
	};
}

function loadMdtProperty(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtPropertyItem {
	let pos = _off;

	const PropFlags = loadE2<PE.CorPropertyAttr>(d, pos);
	pos += PropFlags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Type = ctx.laodBlob(d, pos);
	pos += Type._sz;

	return {
		_off, _sz: pos - _off,
		PropFlags,
		Name,
		Type,
	};
}

function loadMdtMethodSemantics(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMethodSemanticsItem {
	let pos = _off;

	const Semantic = loadE2<PE.CorMethodSemanticsAttr>(d, pos);
	pos += Semantic._sz;

	const Method = ctx.loadRid[PE.MdTableIndex.MethodDef](d, pos);
	pos += Method._sz;

	const Association = ctx.loadCodedToken[MdCodedTokenIndex.HasSemantics](d, pos);
	pos += Association._sz;

	return {
		_off, _sz: pos - _off,
		Semantic,
		Method,
		Association,
	};
}

function loadMdtMethodImpl(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMethodImplItem {
	let pos = _off;

	const Class = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += Class._sz;

	const MethodBody = ctx.loadCodedToken[MdCodedTokenIndex.MethodDefOrRef](d, pos);
	pos += MethodBody._sz;

	const MethodDeclaration = ctx.loadCodedToken[MdCodedTokenIndex.MethodDefOrRef](d, pos);
	pos += MethodDeclaration._sz;

	return {
		_off, _sz: pos - _off,
		Class,
		MethodBody,
		MethodDeclaration,
	};
}

function loadMdtModuleRef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtModuleRefItem {
	let pos = _off;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	return {
		_off, _sz: pos - _off,
		Name,
	};
}

function loadMdtTypeSpec(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtTypeSpecItem {
	let pos = _off;

	const Signature = ctx.laodBlob(d, pos);
	pos += Signature._sz;

	return {
		_off, _sz: pos - _off,
		Signature,
	};
}

function loadMdtImplMap(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtImplMapItem {
	let pos = _off;

	const MappingFlags = loadE2<PE.CorPinvokeMap>(d, pos);
	pos += MappingFlags._sz;

	const MemberForwarded = ctx.loadCodedToken[MdCodedTokenIndex.MemberForwarded](d, pos);
	pos += MemberForwarded._sz;

	const ImportName = ctx.loadStrings(d, pos);
	pos += ImportName._sz;

	const ImportScope = ctx.loadRid[PE.MdTableIndex.ModuleRef](d, pos);
	pos += ImportScope._sz;

	return {
		_off, _sz: pos - _off,
		MappingFlags,
		MemberForwarded,
		ImportName,
		ImportScope,
	};
}

function loadMdtFieldRVA(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFieldRVAItem {
	let pos = _off;

	const RVA = loadU4(d, pos);
	pos += RVA._sz;

	const Field = ctx.loadRid[PE.MdTableIndex.Field](d, pos);
	pos += Field._sz;

	return {
		_off, _sz: pos - _off,
		RVA,
		Field,
	};
}

function loadMdtENCLog(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtENCLogItem {
	let pos = _off;

	const Token = loadU4(d, pos);
	pos += Token._sz;

	const FuncCode = loadU4(d, pos);
	pos += FuncCode._sz;

	return {
		_off, _sz: pos - _off,
		Token,
		FuncCode,
	};
}

function loadMdtENCMap(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtENCMapItem {
	let pos = _off;

	const Token = loadU4(d, pos);
	pos += Token._sz;

	return {
		_off, _sz: pos - _off,
		Token,
	};
}

function loadMdtAssembly(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyItem {
	let pos = _off;

	const HashAlgId = loadE4<PE.AssemblyHashAlgorithm>(d, pos);
	pos += HashAlgId._sz;

	const MajorVersion = loadU2(d, pos);
	pos += MajorVersion._sz;

	const MinorVersion = loadU2(d, pos);
	pos += MinorVersion._sz;

	const BuildNumber = loadU2(d, pos);
	pos += BuildNumber._sz;

	const RevisionNumber = loadU2(d, pos);
	pos += RevisionNumber._sz;

	const Flags = loadE4<PE.CorAssemblyFlags>(d, pos);
	pos += Flags._sz;

	const PublicKey = ctx.laodBlob(d, pos);
	pos += PublicKey._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Locale = ctx.loadStrings(d, pos);
	pos += Locale._sz;

	return {
		_off, _sz: pos - _off,
		HashAlgId,
		MajorVersion,
		MinorVersion,
		BuildNumber,
		RevisionNumber,
		Flags,
		PublicKey,
		Name,
		Locale,
	};
}

function loadMdtAssemblyProcessor(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyProcessorItem {
	let pos = _off;

	const Processor = loadU4(d, pos);
	pos += Processor._sz;

	return {
		_off, _sz: pos - _off,
		Processor,
	};
}

function loadMdtAssemblyOS(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyOSItem {
	let pos = _off;

	const OSPlatformID = loadU4(d, pos);
	pos += OSPlatformID._sz;

	const OSMajorVersion = loadU4(d, pos);
	pos += OSMajorVersion._sz;

	const OSMinorVersion = loadU4(d, pos);
	pos += OSMinorVersion._sz;

	return {
		_off, _sz: pos - _off,
		OSPlatformID,
		OSMajorVersion,
		OSMinorVersion,
	};
}

function loadMdtAssemblyRef(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyRefItem {
	let pos = _off;

	const MajorVersion = loadU2(d, pos);
	pos += MajorVersion._sz;

	const MinorVersion = loadU2(d, pos);
	pos += MinorVersion._sz;

	const BuildNumber = loadU2(d, pos);
	pos += BuildNumber._sz;

	const RevisionNumber = loadU2(d, pos);
	pos += RevisionNumber._sz;

	const Flags = loadE4<PE.CorAssemblyFlags>(d, pos);
	pos += Flags._sz;

	const PublicKeyOrToken = ctx.laodBlob(d, pos);
	pos += PublicKeyOrToken._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Locale = ctx.loadStrings(d, pos);
	pos += Locale._sz;

	const HashValue = ctx.laodBlob(d, pos);
	pos += HashValue._sz;

	return {
		_off, _sz: pos - _off,
		MajorVersion,
		MinorVersion,
		BuildNumber,
		RevisionNumber,
		Flags,
		PublicKeyOrToken,
		Name,
		Locale,
		HashValue,
	};
}

function loadMdtAssemblyRefProcessor(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyRefProcessorItem {
	let pos = _off;

	const Processor = loadU4(d, pos);
	pos += Processor._sz;

	const AssemblyRef = ctx.loadRid[PE.MdTableIndex.AssemblyRef](d, pos);
	pos += AssemblyRef._sz;

	return {
		_off, _sz: pos - _off,
		Processor,
		AssemblyRef,
	};
}

function loadMdtAssemblyRefOS(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtAssemblyRefOSItem {
	let pos = _off;

	const OSPlatformID = loadU4(d, pos);
	pos += OSPlatformID._sz;

	const OSMajorVersion = loadU4(d, pos);
	pos += OSMajorVersion._sz;

	const OSMinorVersion = loadU4(d, pos);
	pos += OSMinorVersion._sz;

	const AssemblyRef = ctx.loadRid[PE.MdTableIndex.AssemblyRef](d, pos);
	pos += AssemblyRef._sz;

	return {
		_off, _sz: pos - _off,
		OSPlatformID,
		OSMajorVersion,
		OSMinorVersion,
		AssemblyRef,
	};
}

function loadMdtFile(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtFileItem {
	let pos = _off;

	const Flags = loadE4<PE.CorFileFlags>(d, pos);
	pos += Flags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const HashValue = ctx.laodBlob(d, pos);
	pos += HashValue._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		Name,
		HashValue,
	};
}

function loadMdtExportedType(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtExportedTypeItem {
	let pos = _off;

	const Flags = loadE4<PE.CorTypeAttr>(d, pos);
	pos += Flags._sz;

	const TypeDefId = loadU4(d, pos);
	pos += TypeDefId._sz;

	const TypeName = ctx.loadStrings(d, pos);
	pos += TypeName._sz;

	const TypeNamespace = ctx.loadStrings(d, pos);
	pos += TypeNamespace._sz;

	const Implementation = ctx.loadCodedToken[MdCodedTokenIndex.Implementation](d, pos);
	pos += Implementation._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		TypeDefId,
		TypeName,
		TypeNamespace,
		Implementation,
	};
}

function loadMdtManifestResource(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtManifestResourceItem {
	let pos = _off;

	const Offset = loadU4(d, pos);
	pos += Offset._sz;

	const Flags = loadE4<PE.CorManifestResourceFlags>(d, pos);
	pos += Flags._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	const Implementation = ctx.loadCodedToken[MdCodedTokenIndex.Implementation](d, pos);
	pos += Implementation._sz;

	return {
		_off, _sz: pos - _off,
		Offset,
		Flags,
		Name,
		Implementation,
	};
}

function loadMdtNestedClass(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtNestedClassItem {
	let pos = _off;

	const NestedClass = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += NestedClass._sz;

	const EnclosingClass = ctx.loadRid[PE.MdTableIndex.TypeDef](d, pos);
	pos += EnclosingClass._sz;

	return {
		_off, _sz: pos - _off,
		NestedClass,
		EnclosingClass,
	};
}

function loadMdtGenericParam(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtGenericParamItem {
	let pos = _off;

	const Number = loadU2(d, pos);
	pos += Number._sz;

	const Flags = loadE2<PE.CorGenericParamAttr>(d, pos);
	pos += Flags._sz;

	const Owner = ctx.loadCodedToken[MdCodedTokenIndex.TypeOrMethodDef](d, pos);
	pos += Owner._sz;

	const Name = ctx.loadStrings(d, pos);
	pos += Name._sz;

	return {
		_off, _sz: pos - _off,
		Number,
		Flags,
		Owner,
		Name,
	};
}

function loadMdtMethodSpec(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtMethodSpecItem {
	let pos = _off;

	const Method = ctx.loadCodedToken[MdCodedTokenIndex.MethodDefOrRef](d, pos);
	pos += Method._sz;

	const Instantiation = ctx.laodBlob(d, pos);
	pos += Instantiation._sz;

	return {
		_off, _sz: pos - _off,
		Method,
		Instantiation,
	};
}

function loadMdtGenericParamConstraint(d: DataView, _off: number, ctx: MdtLoadingContext): PE.MdtGenericParamConstraintItem {
	let pos = _off;

	const Owner = ctx.loadRid[PE.MdTableIndex.GenericParam](d, pos);
	pos += Owner._sz;

	const Constraint = ctx.loadCodedToken[MdCodedTokenIndex.TypeDefOrRef](d, pos);
	pos += Constraint._sz;

	return {
		_off, _sz: pos - _off,
		Owner,
		Constraint,
	};
}

//-----------------------------------------------------------------------------------------------------------------
// IL.
//-----------------------------------------------------------------------------------------------------------------

export function loadIL(pe: PE.PeStruct, m: PE.MdtMethodDefItem): PE.ILMethod {
	if (pe == null || m == null || !U.hasIL(m)) {
		return null;
	}

	let _off = U.rvaToOffset(pe, m.RVA.value);
	let pos = _off;

	const Header = loadILMethodHeader(pe.data, pos);
	pos += Header._sz;

	const end = pos + Header.codeSizeValue;
	const Body = loadFileDataVecByStop(pe.data, pos, i => i._off + i._sz >= end, loadILInst);
	pos += Body._sz;

	const Padding = loadFileData(pe.data, pos, calculatePaddingSize(Body._sz));
	pos += Padding._sz;

	let Sections: PE.FileDataVec<PE.ILMethodSection>;
	if (Header.flagsValue & PE.ILMethodFlags.MoreSects) {
		Sections = loadFileDataVecByStop(pe.data, pos,
			m => !(m.Kind.value & PE.ILMethodSectionKind.MoreSects),
			loadILMethodSection);
		pos += Sections._sz;
	}

	return {
		_off, _sz: pos - _off,
		Header,
		Body,
		Padding,
		Sections
	};
}

function loadILMethodHeader(d: DataView, _off: number): PE.ILMethodHeader {
	const flag = d.getUint8(_off);
	switch (flag & PE.ILMethodFlags.Format__Mask) {
		case PE.ILMethodFlags.Format_TinyFormat:
			return loadILMethodHeaderTiny(d, _off);
		case PE.ILMethodFlags.Format_FatFormat:
			return loadILMethodHeaderFat(d, _off);
		default:
			throw new E.PeError(E.PeErrorType.InvalidMethodHeaderFormat, _off, 1, flag);
	}
}

function loadILMethodHeaderTiny(d: DataView, _off: number): PE.ILMethodHeaderTiny {
	let pos = _off;

	const FlagsAndCodeSize = loadU1(d, pos);
	pos += FlagsAndCodeSize._sz;

	const flagsValue: PE.ILMethodFlags = FlagsAndCodeSize.value & 0x03;
	const codeSizeValue = FlagsAndCodeSize.value >> 2;

	return {
		_off, _sz: pos - _off,
		flagsValue,
		codeSizeValue,
		FlagsAndCodeSize,
	};
}

function loadILMethodHeaderFat(d: DataView, _off: number): PE.ILMethodHeaderFat {
	let pos = _off;

	const Flags = loadE2<PE.ILMethodFlags>(d, pos);
	pos += Flags._sz;

	const MaxStack = loadU2(d, pos);
	pos += MaxStack._sz;

	const CodeSize = loadU4(d, pos);
	pos += CodeSize._sz;

	const LocalVariableSignature = loadMdToken(d, pos);
	pos += LocalVariableSignature._sz;

	return {
		_off, _sz: pos - _off,
		flagsValue: Flags.value,
		codeSizeValue: CodeSize.value,
		Flags,
		MaxStack,
		CodeSize,
		LocalVariableSignature
	};
}

function loadILSwitchOprand(d: DataView, _off: number): PE.ILSwitchOprandField {
	let pos = _off;

	const count = loadU4(d, pos);
	pos += count._sz;

	const targets = loadFileDataVecByCount(d, pos, count.value, loadI4);
	pos += targets._sz;

	return {
		_off, _sz: pos - _off,
		count,
		targets
	};
}

function loadILInst(d: DataView, _off: number): PE.ILInst {
	let pos = _off;

	const opcode = loadOpcode(d, pos);
	pos += opcode._sz;

	let oprand: PE.NumberField | PE.U8Field | PE.I8Field | PE.MdTokenField | PE.ILSwitchOprandField;
	switch (opcode.value) {
		case PE.ILOpcode.nop: break;
		case PE.ILOpcode.break: break;
		case PE.ILOpcode.ldarg_0: break;
		case PE.ILOpcode.ldarg_1: break;
		case PE.ILOpcode.ldarg_2: break;
		case PE.ILOpcode.ldarg_3: break;
		case PE.ILOpcode.ldloc_0: break;
		case PE.ILOpcode.ldloc_1: break;
		case PE.ILOpcode.ldloc_2: break;
		case PE.ILOpcode.ldloc_3: break;
		case PE.ILOpcode.stloc_0: break;
		case PE.ILOpcode.stloc_1: break;
		case PE.ILOpcode.stloc_2: break;
		case PE.ILOpcode.stloc_3: break;
		case PE.ILOpcode.ldarg_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.ldarga_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.starg_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.ldloc_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.ldloca_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.stloc_s: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.ldnull: break;
		case PE.ILOpcode.ldc_i4_m1: break;
		case PE.ILOpcode.ldc_i4_0: break;
		case PE.ILOpcode.ldc_i4_1: break;
		case PE.ILOpcode.ldc_i4_2: break;
		case PE.ILOpcode.ldc_i4_3: break;
		case PE.ILOpcode.ldc_i4_4: break;
		case PE.ILOpcode.ldc_i4_5: break;
		case PE.ILOpcode.ldc_i4_6: break;
		case PE.ILOpcode.ldc_i4_7: break;
		case PE.ILOpcode.ldc_i4_8: break;
		case PE.ILOpcode.ldc_i4_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.ldc_i4: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.ldc_i8: oprand = loadI8(d, pos); break;
		case PE.ILOpcode.ldc_r4: oprand = loadR4(d, pos); break;
		case PE.ILOpcode.ldc_r8: oprand = loadR8(d, pos); break;
		case PE.ILOpcode.dup: break;
		case PE.ILOpcode.pop: break;
		case PE.ILOpcode.jmp: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.call: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.calli: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ret: break;
		case PE.ILOpcode.br_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.brfalse_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.brtrue_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.beq_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.bge_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.bgt_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.ble_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.blt_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.bne_un_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.bge_un_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.bgt_un_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.ble_un_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.blt_un_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.br: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.brfalse: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.brtrue: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.beq: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.bge: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.bgt: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.ble: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.blt: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.bne_un: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.bge_un: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.bgt_un: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.ble_un: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.blt_un: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.switch: oprand = loadILSwitchOprand(d, pos); break;
		case PE.ILOpcode.ldind_i1: break;
		case PE.ILOpcode.ldind_u1: break;
		case PE.ILOpcode.ldind_i2: break;
		case PE.ILOpcode.ldind_u2: break;
		case PE.ILOpcode.ldind_i4: break;
		case PE.ILOpcode.ldind_u4: break;
		case PE.ILOpcode.ldind_i8: break;
		case PE.ILOpcode.ldind_i: break;
		case PE.ILOpcode.ldind_r4: break;
		case PE.ILOpcode.ldind_r8: break;
		case PE.ILOpcode.ldind_ref: break;
		case PE.ILOpcode.stind_ref: break;
		case PE.ILOpcode.stind_i1: break;
		case PE.ILOpcode.stind_i2: break;
		case PE.ILOpcode.stind_i4: break;
		case PE.ILOpcode.stind_i8: break;
		case PE.ILOpcode.stind_r4: break;
		case PE.ILOpcode.stind_r8: break;
		case PE.ILOpcode.add: break;
		case PE.ILOpcode.sub: break;
		case PE.ILOpcode.mul: break;
		case PE.ILOpcode.div: break;
		case PE.ILOpcode.div_un: break;
		case PE.ILOpcode.rem: break;
		case PE.ILOpcode.rem_un: break;
		case PE.ILOpcode.and: break;
		case PE.ILOpcode.or: break;
		case PE.ILOpcode.xor: break;
		case PE.ILOpcode.shl: break;
		case PE.ILOpcode.shr: break;
		case PE.ILOpcode.shr_un: break;
		case PE.ILOpcode.neg: break;
		case PE.ILOpcode.not: break;
		case PE.ILOpcode.conv_i1: break;
		case PE.ILOpcode.conv_i2: break;
		case PE.ILOpcode.conv_i4: break;
		case PE.ILOpcode.conv_i8: break;
		case PE.ILOpcode.conv_r4: break;
		case PE.ILOpcode.conv_r8: break;
		case PE.ILOpcode.conv_u4: break;
		case PE.ILOpcode.conv_u8: break;
		case PE.ILOpcode.callvirt: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.cpobj: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldobj: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldstr: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.newobj: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.castclass: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.isinst: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.conv_r_un: break;
		case PE.ILOpcode.unbox: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.throw: break;
		case PE.ILOpcode.ldfld: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldflda: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.stfld: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldsfld: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldsflda: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.stsfld: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.stobj: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.conv_ovf_i1_un: break;
		case PE.ILOpcode.conv_ovf_i2_un: break;
		case PE.ILOpcode.conv_ovf_i4_un: break;
		case PE.ILOpcode.conv_ovf_i8_un: break;
		case PE.ILOpcode.conv_ovf_u1_un: break;
		case PE.ILOpcode.conv_ovf_u2_un: break;
		case PE.ILOpcode.conv_ovf_u4_un: break;
		case PE.ILOpcode.conv_ovf_u8_un: break;
		case PE.ILOpcode.conv_ovf_i_un: break;
		case PE.ILOpcode.conv_ovf_u_un: break;
		case PE.ILOpcode.box: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.newarr: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldlen: break;
		case PE.ILOpcode.ldelema: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldelem_i1: break;
		case PE.ILOpcode.ldelem_u1: break;
		case PE.ILOpcode.ldelem_i2: break;
		case PE.ILOpcode.ldelem_u2: break;
		case PE.ILOpcode.ldelem_i4: break;
		case PE.ILOpcode.ldelem_u4: break;
		case PE.ILOpcode.ldelem_i8: break;
		case PE.ILOpcode.ldelem_i: break;
		case PE.ILOpcode.ldelem_r4: break;
		case PE.ILOpcode.ldelem_r8: break;
		case PE.ILOpcode.ldelem_ref: break;
		case PE.ILOpcode.stelem_i: break;
		case PE.ILOpcode.stelem_i1: break;
		case PE.ILOpcode.stelem_i2: break;
		case PE.ILOpcode.stelem_i4: break;
		case PE.ILOpcode.stelem_i8: break;
		case PE.ILOpcode.stelem_r4: break;
		case PE.ILOpcode.stelem_r8: break;
		case PE.ILOpcode.stelem_ref: break;
		case PE.ILOpcode.ldelem: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.stelem: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.unbox_any: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.conv_ovf_i1: break;
		case PE.ILOpcode.conv_ovf_u1: break;
		case PE.ILOpcode.conv_ovf_i2: break;
		case PE.ILOpcode.conv_ovf_u2: break;
		case PE.ILOpcode.conv_ovf_i4: break;
		case PE.ILOpcode.conv_ovf_u4: break;
		case PE.ILOpcode.conv_ovf_i8: break;
		case PE.ILOpcode.conv_ovf_u8: break;
		case PE.ILOpcode.refanyval: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ckfinite: break;
		case PE.ILOpcode.mkrefany: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldtoken: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.conv_u2: break;
		case PE.ILOpcode.conv_u1: break;
		case PE.ILOpcode.conv_i: break;
		case PE.ILOpcode.conv_ovf_i: break;
		case PE.ILOpcode.conv_ovf_u: break;
		case PE.ILOpcode.add_ovf: break;
		case PE.ILOpcode.add_ovf_un: break;
		case PE.ILOpcode.mul_ovf: break;
		case PE.ILOpcode.mul_ovf_un: break;
		case PE.ILOpcode.sub_ovf: break;
		case PE.ILOpcode.sub_ovf_un: break;
		case PE.ILOpcode.endfinally: break;
		case PE.ILOpcode.leave: oprand = loadI4(d, pos); break;
		case PE.ILOpcode.leave_s: oprand = loadI1(d, pos); break;
		case PE.ILOpcode.stind_i: break;
		case PE.ILOpcode.conv_u: break;
		case PE.ILOpcode.arglist: break;
		case PE.ILOpcode.ceq: break;
		case PE.ILOpcode.cgt: break;
		case PE.ILOpcode.cgt_un: break;
		case PE.ILOpcode.clt: break;
		case PE.ILOpcode.clt_un: break;
		case PE.ILOpcode.ldftn: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldvirtftn: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.ldarg: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.ldarga: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.starg: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.ldloc: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.ldloca: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.stloc: oprand = loadU4(d, pos); break;
		case PE.ILOpcode.localloc: break;
		case PE.ILOpcode.endfilter: break;
		case PE.ILOpcode.unaligned_: oprand = loadU1(d, pos); break;
		case PE.ILOpcode.volatile_: break;
		case PE.ILOpcode.tail_: break;
		case PE.ILOpcode.initobj: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.constrained_: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.cpblk: break;
		case PE.ILOpcode.initblk: break;
		case PE.ILOpcode.no_: break;
		case PE.ILOpcode.rethrow: break;
		case PE.ILOpcode.sizeof: oprand = loadMdToken(d, pos); break;
		case PE.ILOpcode.refanytype: break;
		case PE.ILOpcode.readonly_: break;
		default: throw new E.PeError(E.PeErrorType.InvalidILOpcode, opcode._off, opcode._sz, <number>opcode.value);
	}
	pos += (oprand) ? oprand._sz : 0;

	return {
		_off, _sz: pos - _off,
		opcode,
		oprand
	};
}

function loadOpcode(d: DataView, _off: number): PE.E1Field<PE.ILOpcode> | PE.E2Field<PE.ILOpcode> {
	chk(d, _off, 1);
	const b = d.getUint8(_off);
	if (b == 0xFE) {
		return loadE2<PE.ILOpcode>(d, _off);
	} else {
		return loadE1<PE.ILOpcode>(d, _off);
	}
}

function loadILMethodSection(d: DataView, _off: number): PE.ILMethodSection {
	let pos = _off;

	const Kind = loadE1<PE.ILMethodSectionKind>(d, pos);
	pos += Kind._sz;

	if (Kind.value & PE.ILMethodSectionKind.FatFormat) {
		const DataSizeBytes = loadFileData(d, pos, 3);
		const dataSize = d.getUint8(pos)
			| (d.getUint8(pos + 1) << 8)
			| (d.getUint8(pos + 2) << 16);
		pos += DataSizeBytes._sz;

		const end = _off + dataSize;
		const Clauses = loadFileDataVecByStop(d, pos,
			i => i._off + i._sz >= end, loadILEHClauseFat);
		pos += Clauses._sz;

		adjustILEHClauseCusage(Clauses.values);

		return {
			_off, _sz: pos - _off,
			Kind,
			DataSizeBytes,
			Clauses,
			dataSize
		};
	}
	else {
		const DataSizeBytes = loadFileData(d, pos, 1);
		const dataSize = d.getUint8(pos);
		pos += DataSizeBytes._sz;

		const Padding = loadFileData(d, pos, 2);
		pos += Padding._sz;

		const end = _off + dataSize;
		const Clauses = loadFileDataVecByStop(d, pos,
			i => i._off + i._sz >= end, loadILEHClauseSmall);
		pos += Clauses._sz;

		adjustILEHClauseCusage(Clauses.values);

		return {
			_off, _sz: pos - _off,
			Kind,
			DataSizeBytes,
			Padding,
			Clauses,
			dataSize
		};
	}
}

function loadILEHClauseSmall(d: DataView, _off: number): PE.ILEHClause {
	let pos = _off;

	const Flags = loadE2<PE.ILEHClauseFlags>(d, pos);
	pos += Flags._sz;

	const TryOffset = loadU2(d, pos);
	pos += TryOffset._sz;

	const TryLength = loadU1(d, pos);
	pos += TryLength._sz;

	const HandlerOffset = loadU2(d, pos);
	pos += HandlerOffset._sz;

	const HandlerLength = loadU1(d, pos);
	pos += HandlerLength._sz;

	const ClassTokenOrFilterOffset = loadU4(d, pos);
	pos += ClassTokenOrFilterOffset._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		TryOffset,
		TryLength,
		HandlerOffset,
		HandlerLength,
		ClassTokenOrFilterOffset,
		usage: PE.ILEHClauseUsage.None
	}
}

function loadILEHClauseFat(d: DataView, _off: number): PE.ILEHClause {
	let pos = _off;

	const Flags = loadE4<PE.ILEHClauseFlags>(d, pos);
	pos += Flags._sz;

	const TryOffset = loadU4(d, pos);
	pos += TryOffset._sz;

	const TryLength = loadU4(d, pos);
	pos += TryLength._sz;

	const HandlerOffset = loadU4(d, pos);
	pos += HandlerOffset._sz;

	const HandlerLength = loadU4(d, pos);
	pos += HandlerLength._sz;

	const ClassTokenOrFilterOffset = loadU4(d, pos);
	pos += ClassTokenOrFilterOffset._sz;

	return {
		_off, _sz: pos - _off,
		Flags,
		TryOffset,
		TryLength,
		HandlerOffset,
		HandlerLength,
		ClassTokenOrFilterOffset,
		usage: PE.ILEHClauseUsage.None
	}
}

function adjustILEHClauseCusage(clauses: PE.ILEHClause[]) {
	let pc: PE.ILEHClause = null;
	for (let c of clauses) {
		switch (c.Flags.value) {
			case PE.ILEHClauseFlags.None:
				c.usage = PE.ILEHClauseUsage.UseClassToken;
				break;
			case PE.ILEHClauseFlags.Filter:
				c.usage = PE.ILEHClauseUsage.UseFilterOffset;
				break;
			case PE.ILEHClauseFlags.Finally:
			case PE.ILEHClauseFlags.Fault:
				if (pc != null
					&& pc.TryOffset.value == c.TryOffset.value
					&& pc.TryLength.value == c.TryLength.value)
					c.usage = pc.usage;
				break;
		}
		pc = c;
	}
}

//-----------------------------------------------------------------------------------------------------------------
// Common Structures.
//-----------------------------------------------------------------------------------------------------------------

function loadU1(d: DataView, _off: number): PE.U1Field {
	chk(d, _off, 1);
	const value = d.getUint8(_off);
	return { _off, _sz: 1, value };
}

function loadU2(d: DataView, _off: number): PE.U2Field {
	chk(d, _off, 2);
	const value = d.getUint16(_off, true);
	return { _off, _sz: 2, value };
}

function loadU4(d: DataView, _off: number): PE.U4Field {
	chk(d, _off, 4);
	const value = d.getUint32(_off, true);
	return { _off, _sz: 4, value };
}

function loadU8(d: DataView, _off: number): PE.U8Field {
	chk(d, _off, 8);
	const low = d.getUint32(_off, true);
	const high = d.getUint32(_off + 4, true);
	return { _off, _sz: 8, low, high };
}

function loadI1(d: DataView, _off: number): PE.I1Field {
	chk(d, _off, 1);
	const value = d.getInt8(_off);
	return { _off, _sz: 1, value };
}

function loadI2(d: DataView, _off: number): PE.I2Field {
	chk(d, _off, 2);
	const value = d.getInt16(_off, true);
	return { _off, _sz: 2, value };
}

function loadI4(d: DataView, _off: number): PE.I4Field {
	chk(d, _off, 4);
	const value = d.getInt32(_off, true);
	return { _off, _sz: 4, value };
}

function loadI8(d: DataView, _off: number): PE.I8Field {
	return loadU8(d, _off);
}

function loadR4(d: DataView, _off: number): PE.R4Field {
	chk(d, _off, 4);
	const value = d.getFloat32(_off, true);
	return { _off, _sz: 4, value };
}

function loadR8(d: DataView, _off: number): PE.R8Field {
	chk(d, _off, 8);
	const value = d.getFloat64(_off, true);
	return { _off, _sz: 8, value };
}

function loadCompressedUint(d: DataView, _off: number): PE.CompressedUintField {
	chk(d, _off, 1);
	const _sz = U.getCompressedIntSize(d.getUint8(_off));
	chk(d, _off, _sz);
	const arr = new Uint8Array(d.buffer.slice(_off, _off + _sz));
	const value = U.decompressUint(arr);
	return { _off, _sz, value };
}

function loadFileData(d: DataView, _off: number, _sz: number): PE.FileData {
	chk(d, _off, _sz);
	return { _off, _sz };
}

function loadFixedSizeAsciiString(d: DataView, _off: number, _sz: number)
	: PE.FixedSizeAsciiStringField {
	chk(d, _off, _sz);
	let len = strlen(d, _off, _sz);
	const bs = new Uint8Array(d.buffer, _off, len);
	const value = <string>String.fromCharCode.apply(null, bs);
	return { _off, _sz, value };
}

function loadFixedSizeUtf8StringField(d: DataView, _off: number, _sz: number)
	: PE.FixedSizeUtf8StringField {
	chk(d, _off, _sz);
	let len = strlen(d, _off, _sz);
	const bs = new Uint8Array(d.buffer, _off, len);
	const ss = Array.from(bs).map(b => "%" + b.toString(16));
	const value = decodeURIComponent(ss.join(""));
	return { _off, _sz, value };
}

function loadNullTerminatedAsciiString(d: DataView, _off: number)
	: PE.NullTerminatedAsciiStringField {
	chk(d, _off, 1);
	let len = strlen(d, _off);
	const bs = new Uint8Array(d.buffer, _off, len);
	const value = <string>String.fromCharCode.apply(null, bs);
	return { _off, _sz: len + 1, value };
}

function loadNullTerminatedUtf8String(d: DataView, _off: number)
	: PE.NullTerminatedUtf8StringField {
	chk(d, _off, 1);
	let len = strlen(d, _off);
	const bs = new Uint8Array(d.buffer, _off, len);
	const ss = Array.from(bs).map(b => "%" + b.toString(16));
	const value = decodeURIComponent(ss.join(""));
	return { _off, _sz: len + 1, value };
}

function loadFixedSizeUnicodeString(d: DataView, _off: number, _sz: number)
	: PE.FixedSizeUnicodeStringField {
	chk(d, _off, _sz);
	if (_sz == 0)
		return { _off, _sz: 0, value: "" };

	const buf = d.buffer.slice(_off, _off + _sz);
	const arr = new Uint16Array(buf);
	const value = String.fromCodePoint.apply(null, arr);
	return { _off, _sz, value };
}

function strlen(d: DataView, _off: number, max?: number): number {
	chk(d, _off, 1);

	let ml = d.byteLength - _off;
	if (max && max < ml)
		ml = max;

	const tb = new Uint8Array(d.buffer, _off);
	let len = 0;
	while (tb[len] != 0 && len < ml)
		len++;

	return len;
}

function loadE1<T>(d: DataView, _off: number): PE.E1Field<T> {
	chk(d, _off, 1);
	const value = d.getUint8(_off) as any as T;
	return { _off, _sz: 1, value };
}

function loadE2<T>(d: DataView, _off: number): PE.E2Field<T> {
	chk(d, _off, 2);
	const value = d.getUint16(_off, true) as any as T;
	return { _off, _sz: 2, value };
}

function loadE4<T>(d: DataView, _off: number): PE.E4Field<T> {
	chk(d, _off, 4);
	const value = d.getUint32(_off, true) as any as T;
	return { _off, _sz: 4, value };
}

function loadFileDataVecByCount<T extends PE.FileData>(d: DataView, _off: number,
	count: number, load: (d: DataView, o: number) => T): PE.FileDataVec<T> {
	let values: T[] = [];
	let pos = _off;
	for (let i = 0; i < count; i++) {
		const item = load(d, pos);
		pos += item._sz;
		values.push(item);
	}
	return { _off, _sz: pos - _off, values };
}

function loadFileDataVecByStop<T extends PE.FileData>(d: DataView, _off: number,
	stop: (item: T) => boolean,
	load: (d: DataView, o: number) => T): PE.FileDataVec<T> {
	let values: T[] = [];
	let pos = _off;
	let item: T;
	do {
		item = load(d, pos);
		pos += item._sz;
		values.push(item);
	} while (!stop(item));
	return { _off, _sz: pos - _off, values };
}

function loadMdCodedToken4(d: DataView, _off: number, cti: MdCodedTokenInfo): PE.MdCodedTokenField {
	chk(d, _off, 4);
	const value = d.getUint32(_off, true);
	return Object.assign({ _off, _sz: 4 }, decodeCodedToken(value, cti));
}

function loadMdCodedToken2(d: DataView, _off: number, cti: MdCodedTokenInfo): PE.MdCodedTokenField {
	chk(d, _off, 4);
	const value = d.getUint16(_off, true);
	return Object.assign({ _off, _sz: 2 }, decodeCodedToken(value, cti));
}

function decodeCodedToken(token: number, cti: MdCodedTokenInfo): { tid: PE.MdTableIndex, rid: number } {
	const tid = cti.tables[token & ((1 << cti.tagSize) - 1)];
	const rid = token >> cti.tagSize;
	return { tid, rid };
}

function loadMdToken(d: DataView, _off: number): PE.MdTokenField {
	chk(d, _off, 4);
	const value = d.getUint32(_off, true);
	const tid: PE.MdTableIndex = (value & 0xFF000000) >> 24;
	const rid = value & 0x00FFFFFF;
	return { _off, _sz: 4, tid, rid };
}

function calculatePaddingSize(dataSize: number, packSize: number = 4): number {
	const rem = dataSize % packSize;
	return rem == 0 ? 0 : packSize - rem;
}

function count1(n: number) {
	let c = 0;
	for (let i = 0, mask = 1; i < 32; i++ , mask <<= 1) {
		if (n & mask)
			c++;
	}
	return c;
}

//-----------------------------------------------------------------------------------------------------------------
// Error Checking.
//-----------------------------------------------------------------------------------------------------------------

function chk_fsz(sz: number) {
	if (sz <= 0x80)
		throw new E.PeError(E.PeErrorType.FileTooShort, 0, sz);
	else if (sz >= 0x80000000)
		throw new E.PeError(E.PeErrorType.FileTooLong, 0, sz);
}

function chk(d: DataView, _off: number, _sz: number) {
	if (_off < 0 || _off >= d.byteLength)
		throw new E.PeError(E.PeErrorType.InvalidOffset, _off, _sz);
	if (_sz < 0 || _off + _sz > d.byteLength)
		throw new E.PeError(E.PeErrorType.InvalidSize, _off, _sz);
}

function chk_fp(d: DataView, field: PE.NumberField, wantedSize: number) {
	if (field.value < 0 || field.value + wantedSize > d.byteLength)
		throw new E.PeError(E.PeErrorType.InvalidFilePointer,
			field._off, field._sz, field.value);
}

function err(e: E.PeErrorType, d: PE.NumberField) {
	throw new E.PeError(e, d._off, d._sz, d.value);
}
