/// <reference path="./struct.ts" />
/// <reference path="./error.ts" />

import * as PE from "./struct";
import * as E from "./error";

export function copyData(pe: PE.PeStruct, data: PE.FileData): ArrayBuffer {
	return pe.data.buffer.slice(data._off, data._off + data._sz);
}

export function is64Bit(pe: PE.PeStruct): boolean {
	return pe.optionalHeader.Magic.value == PE.ntOptHdr64Magic;
}

export function isDll(pe: PE.PeStruct): boolean {
	return (pe.fileHeader.Characteristics.value & PE.FileAttr.IMAGE_FILE_DLL) != 0;
}

export function rvaToOffset(pe: PE.PeStruct, rva: number): number {
	var sh = getSectionHeaderByRva(pe, rva);
	if (sh == null)
		return 0;

	return rva - sh.VirtualAddress.value + sh.PointerToRawData.value;
}

export function offsetToRva(pe: PE.PeStruct, offset: number): number {
	var sh = getSectionHeaderByOffset(pe, offset);
	if (sh == null)
		return 0;

	return offset - sh.PointerToRawData.value + sh.VirtualAddress.value;
}

export function getSectionHeaderByRva(pe: PE.PeStruct, rva: number): PE.SectionHeader {
	if (pe.sectionHeaders == null)
		return null;

	for (let sh of pe.sectionHeaders.values) {
		if (rva >= sh.VirtualAddress.value
			&& rva < sh.VirtualAddress.value + sh.VirtualSize.value)
			return sh;
	}

	return null;
}

export function getSectionHeaderByOffset(pe: PE.PeStruct, offset: number): PE.SectionHeader {
	if (pe.sectionHeaders == null)
		return null;

	for (let sh of pe.sectionHeaders.values) {
		if (offset >= sh.PointerToRawData.value
			&& offset < sh.PointerToRawData.value + sh.VirtualSize.value)
			return sh;
	}

	return null;
}

export function hasMetadata(pe: PE.PeStruct): boolean {
	const dd = pe.optionalHeader.DataDirectories
		.values[PE.DataDirectoryIndex.ComDescriptor];
	return dd.Rva.value > 0 && dd.Size.value > 0;
}

export function hasManRes(pe: PE.PeStruct): boolean {
	return (hasMetadata(pe)
		&& pe.cliHeader.Resources.Rva.value > 0
		&& pe.cliHeader.Resources.Size.value > 0);
}

export function hasSNSignature(pe: PE.PeStruct): boolean {
	return (hasMetadata(pe)
		&& pe.cliHeader.StrongNameSignature.Rva.value > 0
		&& pe.cliHeader.StrongNameSignature.Size.value > 0);
}

export function hasIL(methodDef: PE.MdtMethodDefItem): boolean {
	return (methodDef.RVA.value > 0
		&& (methodDef.ImplFlags.value & PE.CorMethodImpl.ct__Mask) == PE.CorMethodImpl.ct_IL
		&& (methodDef.ImplFlags.value & PE.CorMethodImpl.m__Mask) == PE.CorMethodImpl.m_Managed);
}

export function decompressUint(data: Uint8Array): number {
	if ((data[0] & 0x80) == 0 && data.buffer.byteLength == 1)
		return data[0];
	else if ((data[0] & 0xC0) == 0x80 && data.buffer.byteLength == 2)
		return (data[0] & 0x3F) << 8 | data[1];
	else if ((data[0] & 0xE0) == 0xC0 && data.buffer.byteLength == 4)
		return (data[0] & 0x1F) << 24 | data[1] << 16 | data[2] << 8 | data[3];
	else
		throw new RangeError();
}

export function decompressInt(data: Uint8Array): number {
	const u = decompressUint(data);
	if ((u & 0x00000001) == 0)
		return (u >> 1);

	const fb = data[0];
	if ((fb & 0x80) == 0)
		return (u >> 1) | 0xFFFFFFC0;
	else if ((fb & 0xC0) == 0x80)
		return (u >> 1) | 0xFFFFE000;
	else if ((fb & 0xE0) == 0xC0)
		return (u >> 1) | 0xF0000000;
	else
		throw new RangeError();
}

export function getCompressedIntSize(firstByte: number): number {
	if ((firstByte & 0xFFFFFF00) != 0)
		throw new RangeError();
	else if ((firstByte & 0x80) == 0)
		return 1;
	else if ((firstByte & 0xC0) == 0x80)
		return 2;
	else if ((firstByte & 0xE0) == 0xC0)
		return 4;
	else
		throw new RangeError();
}
