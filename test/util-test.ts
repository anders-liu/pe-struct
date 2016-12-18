/// <reference path="../typings/index.d.ts" />
/// <reference path="../def/pe-struct.d.ts" />

import * as PE from "pe-struct";
import { TestCases, expectError } from "./test-util";

describe("PeUtil Tests", () => {
	const pe32 = TestCases.load("Simple.X86.exe__");
	const pe64 = TestCases.load("Simple.X64.exe__");
	const peDll = TestCases.load("Simple.dll__");
	const peNative = TestCases.load("SimpleNativeApp.exe__");
	const peFullMD = TestCases.load("FullMetadataTables.Assembly.exe__");
	const peSigned = TestCases.load("Simple.Signed.exe__");

	test("copyData", () => {
		const buf = PE.copyData(pe32, { _off: 0, _sz: 2 });
		const arr = new Uint8Array(buf);
		expect(arr).toEqual(Uint8Array.from([0x4D, 0x5A]));
	});

	test("is64Bit", () => {
		expect(PE.is64Bit(pe32)).toEqual(false);
		expect(PE.is64Bit(pe64)).toEqual(true);
	});

	test("isDll", () => {
		expect(PE.isDll(pe32)).toEqual(false);
		expect(PE.isDll(peDll)).toEqual(true);
	});

	test("rvaToOffset", () => {
		expect(PE.rvaToOffset(pe32, 0x2000)).toEqual(0x200);
		expect(PE.rvaToOffset(pe32, 0x44E3)).toEqual(0xAE3);
		expect(PE.rvaToOffset(pe32, 0x44E4)).toEqual(0);
		expect(PE.rvaToOffset(pe32, 0xFFFFFFFF)).toEqual(0);
	});

	test("offsetToRva", () => {
		expect(PE.offsetToRva(pe32, 0x200)).toEqual(0x2000);
		expect(PE.offsetToRva(pe32, 0xAE3)).toEqual(0x44E3);
		expect(PE.offsetToRva(pe32, 0xAE4)).toEqual(0);
		expect(PE.offsetToRva(pe32, 0xFFFFFFFF)).toEqual(0);
	});

	test("getSectionHeaderByRva", () => {
		expect(PE.getSectionHeaderByRva(pe32, 0x2000)).toEqual(pe32.sectionHeaders.values[0]);
		expect(PE.getSectionHeaderByRva(pe32, 0x44E3)).toEqual(pe32.sectionHeaders.values[1]);
		expect(PE.getSectionHeaderByRva(pe32, 0x44E4)).toBeNull();
		expect(PE.getSectionHeaderByRva(pe32, 0xFFFFFFFF)).toBeNull();
	});

	test("getSectionHeaderByOffset", () => {
		expect(PE.getSectionHeaderByOffset(pe32, 0x200)).toEqual(pe32.sectionHeaders.values[0]);
		expect(PE.getSectionHeaderByOffset(pe32, 0xAE3)).toEqual(pe32.sectionHeaders.values[1]);
		expect(PE.getSectionHeaderByOffset(pe32, 0xAE4)).toBeNull();
		expect(PE.getSectionHeaderByOffset(pe32, 0xFFFFFFFF)).toBeNull();
	});

	test("hasMetadata", () => {
		expect(PE.hasMetadata(pe32)).toEqual(true);
		expect(PE.hasMetadata(pe64)).toEqual(true);
		expect(PE.hasMetadata(peNative)).toEqual(false);
	});

	test("hasManRes", () => {
		expect(PE.hasManRes(pe32)).toEqual(false);
		expect(PE.hasManRes(peFullMD)).toEqual(true);
	});

	test("hasSNSignature", () => {
		expect(PE.hasSNSignature(pe32)).toEqual(false);
		expect(PE.hasSNSignature(peSigned)).toEqual(true);
	});

	test("hasIL", () => {
		expect(PE.hasIL(pe32.mdtMethodDef.values[0])).toEqual(true);
		expect(PE.hasIL(pe32.mdtMethodDef.values[1])).toEqual(true);
	});

	test("decompressUint", () => {
		const tf = (d: number[], e: number) =>
			expect(PE.decompressUint(Uint8Array.from(d))).toEqual(e);

		tf([0], 0);
		tf([0x7F], 0x7F);
		tf([0x80, 0x80], 0x80);
		tf([0xBF, 0xFF], 0x3FFF);
		tf([0xC0, 0x00, 0x40, 0x00], 0x4000);
		tf([0xDF, 0xFF, 0xFF, 0xFF], 0x1FFFFFFF);
	});

	test("decompressUint - RangeError", () => {
		const tf = (d: number[]) =>
			PE.decompressUint(Uint8Array.from(Uint8Array.from(d)));

		expectError(() => tf([0xE0, 0x00, 0x00, 0x00]));
		expectError(() => tf([0xFF, 0xFF, 0xFF, 0xFF]));
	});

	test("decompressInt", () => {
		const tf = (d: number[], e: number) =>
			expect(PE.decompressInt(Uint8Array.from(d))).toEqual(e);

		tf([0], 0);
		tf([0x7E], 0x3F);
		tf([0x01], -64);
		tf([0x80, 0x80], 0x40);
		tf([0xBF, 0x7F], -65);
		tf([0xBF, 0xFE], 0x1FFF);
		tf([0x80, 0x01], -8192);
		tf([0xC0, 0x00, 0x40, 0x00], 0x2000);
		tf([0xDF, 0xFF, 0xBF, 0xFF], -8193);
		tf([0xDF, 0xFF, 0xFF, 0xFE], 0x0FFFFFFF);
		tf([0xC0, 0x00, 0x00, 0x01], -268435456);
	});

	test("decompressInt - RangeError", () => {
		const tf = (d: number[]) =>
			PE.decompressInt(Uint8Array.from(Uint8Array.from(d)));

		expectError(() => tf([0xE0, 0x00, 0x00, 0x00]));
		expectError(() => tf([0xFF, 0xFF, 0xFF, 0xFF]));
	});

	test("getCompressedIntSize", () => {
		expect(PE.getCompressedIntSize(0)).toEqual(1);
		expect(PE.getCompressedIntSize(0x7F)).toEqual(1);
		expect(PE.getCompressedIntSize(0x80)).toEqual(2);
		expect(PE.getCompressedIntSize(0xBF)).toEqual(2);
		expect(PE.getCompressedIntSize(0xC0)).toEqual(4);
		expect(PE.getCompressedIntSize(0xDF)).toEqual(4);
	});

	test("getCompressedIntSize - RangeError", () => {
		expectError(() => PE.getCompressedIntSize(0xE0));
		expectError(() => PE.getCompressedIntSize(0xFF7F));
	});
});
