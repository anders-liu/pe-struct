/// <reference path="../typings/index.d.ts" />
/// <reference path="../def/pe-struct.d.ts" />

import * as PE from "pe-struct";
import * as FS from "fs";
import { TestCases, expectPeError } from "./test-util";

describe("PeLoader", () => {
	describe("Headers", () => {
		const pe32 = TestCases.load("Simple.X86.exe__");
		const pe64 = TestCases.load("Simple.X64.exe__");

		test("dosHeader", () => {
			const d = pe32.dosHeader;

			expect(d.e_magic._off).toEqual(0);
			expect(d.e_magic._sz).toEqual(2);
			expect(d.e_magic.value).toEqual(PE.dosSignature);

			expect(d.e_lfanew._off).toEqual(0x3C);
			expect(d.e_lfanew._sz).toEqual(4);
			expect(d.e_lfanew.value).toEqual(0x80);

			expect(d._off).toEqual(0);
			expect(d._sz).toEqual(64);
		});

		test("peSignature", () => {
			const d = pe32.peSignature;

			expect(d._off).toEqual(pe32.dosHeader.e_lfanew.value);
			expect(d._sz).toEqual(4);
			expect(d.value).toEqual(PE.ntSignature);
		});

		test("fileHeader - 32", () => {
			const d = pe32.fileHeader;

			expect(d.Machine._off).toEqual(d._off);
			expect(d.Machine._sz).toEqual(2);
			expect(d.Machine.value).toEqual(PE.FileMachine.IMAGE_FILE_MACHINE_I386);

			expect(d.NumberOfSections._off).toEqual(d.Machine._off + d.Machine._sz);
			expect(d.NumberOfSections._sz).toEqual(2);
			expect(d.NumberOfSections.value).toEqual(3);

			expect(d.SizeOfOptionalHeader.value).toEqual(PE.sizeOfOptHdr32);

			expect(d._off).toEqual(pe32.peSignature._off + pe32.peSignature._sz);
			expect(d._sz).toEqual(20);
		});

		test("fileHeader - 64", () => {
			const d = pe64.fileHeader;

			expect(d.Machine._off).toEqual(d._off);
			expect(d.Machine._sz).toEqual(2);
			expect(d.Machine.value).toEqual(PE.FileMachine.IMAGE_FILE_MACHINE_AMD64);

			expect(d.NumberOfSections._off).toEqual(d.Machine._off + d.Machine._sz);
			expect(d.NumberOfSections._sz).toEqual(2);
			expect(d.NumberOfSections.value).toEqual(2);

			expect(d.SizeOfOptionalHeader.value).toEqual(PE.sizeOfOptHdr64);

			expect(d._off).toEqual(pe64.peSignature._off + pe64.peSignature._sz);
			expect(d._sz).toEqual(20);
		});

		test("optionalHeader - 32", () => {
			const d = pe32.optionalHeader as PE.OptionalHeader32;

			expect(d.Magic.value).toEqual(PE.ntOptHdr32Magic);
			expect(d.BaseOfCode.value).toEqual(0x2000);
			expect(d.Subsystem.value).toEqual(0x03);
			expect(d.NumberOfRvaAndSizes.value).toEqual(16);

			expect(d._off).toEqual(pe32.fileHeader._off + pe32.fileHeader._sz);
			expect(d._sz).toEqual(224);
		});

		test("optionalHeader - 64", () => {
			const d = pe64.optionalHeader as PE.OptionalHeader64;

			expect(d.Magic.value).toEqual(PE.ntOptHdr64Magic);
			expect(d.BaseOfCode.value).toEqual(0x2000);
			expect(d.Subsystem.value).toEqual(0x03);
			expect(d.NumberOfRvaAndSizes.value).toEqual(16);

			expect(d.SizeOfStackReserve.high).toEqual(0);
			expect(d.SizeOfStackReserve.low).toEqual(0x400000);
			expect(d.SizeOfStackCommit.high).toEqual(0);
			expect(d.SizeOfStackCommit.low).toEqual(0x4000);
			expect(d.SizeOfHeapReserve.high).toEqual(0);
			expect(d.SizeOfHeapReserve.low).toEqual(0x100000);
			expect(d.SizeOfHeapCommit.high).toEqual(0);
			expect(d.SizeOfHeapCommit.low).toEqual(0x2000);

			expect(d._off).toEqual(pe64.fileHeader._off + pe64.fileHeader._sz);
			expect(d._sz).toEqual(240);
		});

		test("sectionHeaders", () => {
			const d = pe32.sectionHeaders;

			expect(d._off).toEqual(pe32.optionalHeader._off + pe32.optionalHeader._sz);
			expect(d._sz).toEqual(40 * d.values.length);
			expect(d.values.length).toEqual(3);

			const sh = d.values[0];

			expect(sh.Name.value).toEqual(".text");
			expect(sh.VirtualSize.value).toEqual(0x3C4);
			expect(sh.VirtualAddress.value).toEqual(0x2000);
			expect(sh.Characteristics.value).toEqual(
				PE.SectionAttr.IMAGE_SCN_CNT_CODE |
				PE.SectionAttr.IMAGE_SCN_MEM_READ |
				PE.SectionAttr.IMAGE_SCN_MEM_EXECUTE
			);

			expect(sh._off).toEqual(d._off);
			expect(sh._sz).toEqual(40);
		});
	});

	describe("Metadata", () => {
		const pe32 = TestCases.load("Simple.X86.exe__");
		const peChs = TestCases.load("Chinese.dll__");
		const peFull = TestCases.load("FullMetadataTables.Assembly.exe__");
		const peFrva = TestCases.load("FieldRva.exe__");

		test("cliHeader", () => {
			const d = pe32.cliHeader;

			expect(d.cb.value).toEqual(d._sz);

			expect(d.MetaData.Rva.value).toBeGreaterThan(0);
			expect(d.MetaData.Size.value).toBeGreaterThan(0);

			expect(d._off).toEqual(0x208);
			expect(d._sz).toEqual(72);
		});

		test("mdRoot", () => {
			const d = pe32.mdRoot;

			expect(d.VersionLength.value)
				.toEqual(d.Version._sz + d.VersionPadding._sz);
			expect(d.Version._sz).toEqual(11);
			expect(d.Version.value).toEqual("v4.0.30319");
			expect(d.NumberOfStreams.value).toEqual(5);

			expect(d._off).toEqual(0x268);
			expect(d._sz).toEqual(108);

			expect(d.StreamHeaders.values[0].Name.value).toEqual("#~");
			expect(d.StreamHeaders.values[0].Padding._sz).toEqual(1);
			expect(d.StreamHeaders.values[1].Name.value).toEqual("#Strings");
			expect(d.StreamHeaders.values[1].Padding._sz).toEqual(3);
			expect(d.StreamHeaders.values[2].Name.value).toEqual("#US");
			expect(d.StreamHeaders.values[2].Padding._sz).toEqual(0);
			expect(d.StreamHeaders.values[3].Name.value).toEqual("#GUID");
			expect(d.StreamHeaders.values[3].Padding._sz).toEqual(2);
			expect(d.StreamHeaders.values[4].Name.value).toEqual("#Blob");
			expect(d.StreamHeaders.values[4].Padding._sz).toEqual(2);
		});

		test("mdsStrings", () => {
			const d = pe32.mdsStrings;

			expect(d.values.length).toEqual(19);

			expect(d.values[0]._off).toEqual(976);
			expect(d.values[0]._sz).toEqual(1);
			expect(d.values[0].value).toEqual("");

			expect(d.values[1]._off).toEqual(977);
			expect(d.values[1]._sz).toEqual(11);
			expect(d.values[1].value).toEqual("Simple.X86");

			expect(d.values[18]._off).toEqual(1249);
			expect(d.values[18]._sz).toEqual(7);
			expect(d.values[18].value).toEqual("Object");
		});

		test("mdsStrings - Chinese", () => {
			const d = peChs.mdsStrings;

			expect(d.values.length).toEqual(16);

			expect(d.values[15]._off).toEqual(1223);
			expect(d.values[15]._sz).toEqual(13);
			expect(d.values[15].value).toEqual("中文方法");
		});

		test("mdsUS", () => {
			const d = pe32.mdsUS;

			expect(d.values.length).toEqual(5);

			expect(d.values[0].compressedSize.value).toEqual(0);
			expect(d.values[0].userString._sz).toEqual(0);
			expect(d.values[0].suffix._sz).toEqual(0);

			expect(d.values[1].compressedSize.value).toEqual(27);
			expect(d.values[1].userString.value).toEqual("Hello, world!");
			expect(d.values[1].suffix._sz).toEqual(1);
			expect(pe32.data.getUint8(d.values[1].suffix._off)).toEqual(0);
		});

		test("mdsUS - Chinese", () => {
			const d = peChs.mdsUS;
			const s = d.values[1];
			expect(s.compressedSize.value).toEqual(13);
			expect(s.userString._sz).toEqual(12);
			expect(s.userString.value).toEqual("世界，你好！");
			expect(s.suffix._sz).toEqual(1);
			expect(peChs.data.getUint8(s.suffix._off)).toEqual(1);
		});

		test("mdsGuid", () => {
			const d = pe32.mdsGuid;

			expect(d.values.length).toEqual(1);

			const expected = Uint8Array.from([
				0xEE, 0x22, 0xA7, 0xC3, 0x23, 0xB5, 0x65, 0x4A,
				0xB6, 0xDA, 0xED, 0x1C, 0xF3, 0x6F, 0x73, 0x69]);
			expect(d.values[0]._off).toEqual(1288);
			expect(d.values[0]._sz).toEqual(16);
			expect(new Uint8Array(PE.copyData(pe32, d.values[0]))).toEqual(expected);
		});

		test("mdsBlob", () => {
			const d = pe32.mdsBlob;

			expect(d.values.length).toEqual(11);

			expect(d.values[0].compressedSize.value).toEqual(0);
			expect(d.values[0].data._sz).toEqual(0);

			expect(d.values[5]._off).toEqual(1325);
			expect(d.values[5]._sz).toEqual(9);
			expect(d.values[5].compressedSize.value).toEqual(8);
			expect(d.values[5].data._sz).toEqual(8);
			const expected = Uint8Array.from([0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89]);
			const actual = new Uint8Array(PE.copyData(pe32, d.values[5].data));
			expect(actual).toEqual(expected);

			expect(d.values[10].compressedSize.value).toEqual(0);
			expect(d.values[10].data._sz).toEqual(0);
		});

		test("mdTableHeader", () => {
			const d = pe32.mdTableHeader;

			expect(d.MajorVersion.value).toEqual(2);
			expect(d.MinorVersion.value).toEqual(0);
			expect(d.Valid.high.toString(2)).toEqual("1001");
			expect(d.Valid.low.toString(2)).toEqual("1010001000111");
			expect(d.Sorted.high.toString(2)).toEqual("1011000000000");
			expect(d.Sorted.low.toString(2)).toEqual("110011000000011111101000000000");
			expect(d.Rows.values.length).toEqual(8);
			expect(d.Rows.values.map(r => r.value)).toEqual([1, 6, 2, 2, 5, 3, 1, 1]);

			expect(d._off).toEqual(724);
			expect(d._sz).toEqual(56);
		});

		test("mdTableRows", () => {
			const d = pe32.mdTableRows;
			expect(d[PE.MdTableIndex.Module]).toEqual(1);
			expect(d[PE.MdTableIndex.TypeRef]).toEqual(6);
			expect(d[PE.MdTableIndex.TypeDef]).toEqual(2);
			expect(d[PE.MdTableIndex.FieldPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Field]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodDef]).toEqual(2);
			expect(d[PE.MdTableIndex.ParamPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Param]).toEqual(0);
			expect(d[PE.MdTableIndex.InterfaceImpl]).toEqual(0);
			expect(d[PE.MdTableIndex.MemberRef]).toEqual(5);
			expect(d[PE.MdTableIndex.Constant]).toEqual(0);
			expect(d[PE.MdTableIndex.CustomAttribute]).toEqual(3);
			expect(d[PE.MdTableIndex.FieldMarshal]).toEqual(0);
			expect(d[PE.MdTableIndex.DeclSecurity]).toEqual(0);
			expect(d[PE.MdTableIndex.ClassLayout]).toEqual(0);
			expect(d[PE.MdTableIndex.FieldLayout]).toEqual(0);
			expect(d[PE.MdTableIndex.StandAloneSig]).toEqual(0);
			expect(d[PE.MdTableIndex.EventMap]).toEqual(0);
			expect(d[PE.MdTableIndex.EventPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Event]).toEqual(0);
			expect(d[PE.MdTableIndex.PropertyMap]).toEqual(0);
			expect(d[PE.MdTableIndex.PropertyPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Property]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodSemantics]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodImpl]).toEqual(0);
			expect(d[PE.MdTableIndex.ModuleRef]).toEqual(0);
			expect(d[PE.MdTableIndex.TypeSpec]).toEqual(0);
			expect(d[PE.MdTableIndex.ImplMap]).toEqual(0);
			expect(d[PE.MdTableIndex.FieldRVA]).toEqual(0);
			expect(d[PE.MdTableIndex.ENCLog]).toEqual(0);
			expect(d[PE.MdTableIndex.ENCMap]).toEqual(0);
			expect(d[PE.MdTableIndex.Assembly]).toEqual(1);
			expect(d[PE.MdTableIndex.AssemblyProcessor]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyOS]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyRef]).toEqual(1);
			expect(d[PE.MdTableIndex.AssemblyRefProcessor]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyRefOS]).toEqual(0);
			expect(d[PE.MdTableIndex.File]).toEqual(0);
			expect(d[PE.MdTableIndex.ExportedType]).toEqual(0);
			expect(d[PE.MdTableIndex.ManifestResource]).toEqual(0);
			expect(d[PE.MdTableIndex.NestedClass]).toEqual(0);
			expect(d[PE.MdTableIndex.GenericParam]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodSpec]).toEqual(0);
			expect(d[PE.MdTableIndex.GenericParamConstraint]).toEqual(0);
		});

		test("mdTableHeader - Full Tables", () => {
			const d = peFull.mdTableHeader;

			expect(d.MajorVersion.value).toEqual(2);
			expect(d.MinorVersion.value).toEqual(0);
			expect(d.Valid.high.toString(2)).toEqual("1111111001001");
			expect(d.Valid.low.toString(2)).toEqual("11111101101111111111101010111");
			expect(d.Sorted.high.toString(2)).toEqual("1011000000000");
			expect(d.Sorted.low.toString(2)).toEqual("110011000000011111101000000000");
			expect(d.Rows.values.length).toEqual(33);
			expect(d.Rows.values.map(r => r.value)).toEqual([
				1, 29, 12, 26, 33, 19, 3, 25, 4, 23, 6, 1, 2, 7, 8,
				1, 2, 2, 3, 10, 1, 2, 2, 1, 1, 1, 1, 1, 1, 2, 4, 3, 2]);

			expect(d._off).toEqual(1400);
			expect(d._sz).toEqual(156);
		});

		test("mdTableRows - Full Tables", () => {
			const d = peFull.mdTableRows;
			expect(d[PE.MdTableIndex.Module]).toEqual(1);
			expect(d[PE.MdTableIndex.TypeRef]).toEqual(29);
			expect(d[PE.MdTableIndex.TypeDef]).toEqual(12);
			expect(d[PE.MdTableIndex.FieldPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Field]).toEqual(26);
			expect(d[PE.MdTableIndex.MethodPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.MethodDef]).toEqual(33);
			expect(d[PE.MdTableIndex.ParamPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Param]).toEqual(19);
			expect(d[PE.MdTableIndex.InterfaceImpl]).toEqual(3);
			expect(d[PE.MdTableIndex.MemberRef]).toEqual(25);
			expect(d[PE.MdTableIndex.Constant]).toEqual(4);
			expect(d[PE.MdTableIndex.CustomAttribute]).toEqual(23);
			expect(d[PE.MdTableIndex.FieldMarshal]).toEqual(6);
			expect(d[PE.MdTableIndex.DeclSecurity]).toEqual(1);
			expect(d[PE.MdTableIndex.ClassLayout]).toEqual(2);
			expect(d[PE.MdTableIndex.FieldLayout]).toEqual(7);
			expect(d[PE.MdTableIndex.StandAloneSig]).toEqual(8);
			expect(d[PE.MdTableIndex.EventMap]).toEqual(1);
			expect(d[PE.MdTableIndex.EventPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Event]).toEqual(2);
			expect(d[PE.MdTableIndex.PropertyMap]).toEqual(2);
			expect(d[PE.MdTableIndex.PropertyPtr]).toEqual(0);
			expect(d[PE.MdTableIndex.Property]).toEqual(3);
			expect(d[PE.MdTableIndex.MethodSemantics]).toEqual(10);
			expect(d[PE.MdTableIndex.MethodImpl]).toEqual(1);
			expect(d[PE.MdTableIndex.ModuleRef]).toEqual(2);
			expect(d[PE.MdTableIndex.TypeSpec]).toEqual(2);
			expect(d[PE.MdTableIndex.ImplMap]).toEqual(1);
			expect(d[PE.MdTableIndex.FieldRVA]).toEqual(0);
			expect(d[PE.MdTableIndex.ENCLog]).toEqual(0);
			expect(d[PE.MdTableIndex.ENCMap]).toEqual(0);
			expect(d[PE.MdTableIndex.Assembly]).toEqual(1);
			expect(d[PE.MdTableIndex.AssemblyProcessor]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyOS]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyRef]).toEqual(1);
			expect(d[PE.MdTableIndex.AssemblyRefProcessor]).toEqual(0);
			expect(d[PE.MdTableIndex.AssemblyRefOS]).toEqual(0);
			expect(d[PE.MdTableIndex.File]).toEqual(1);
			expect(d[PE.MdTableIndex.ExportedType]).toEqual(1);
			expect(d[PE.MdTableIndex.ManifestResource]).toEqual(1);
			expect(d[PE.MdTableIndex.NestedClass]).toEqual(2);
			expect(d[PE.MdTableIndex.GenericParam]).toEqual(4);
			expect(d[PE.MdTableIndex.MethodSpec]).toEqual(3);
			expect(d[PE.MdTableIndex.GenericParamConstraint]).toEqual(2);
		});

		test("mdTableRows - FieldRVA", () => {
			const d = peFrva.mdTableRows;
			expect(d[PE.MdTableIndex.FieldRVA]).toEqual(1);
		});
	});

	describe("Metadata Tables", () => {
		const pe = TestCases.load("FullMetadataTables.Assembly.exe__");
		const peFieldRVA = TestCases.load("FieldRva.exe__");

		test("mdtModule", () => {
			const d = pe.mdtModule;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Module]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Generation._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Mvid._sz).toEqual(2);
			expect(d.values[0].EncId._sz).toEqual(2);
			expect(d.values[0].EncBaseId._sz).toEqual(2);

			expect(d.values[0].Generation.value).toEqual(0);
			expect(d.values[0].Name.value).toEqual(1113);
			expect(d.values[0].Mvid.value).toEqual(1);
			expect(d.values[0].EncId.value).toEqual(0);
			expect(d.values[0].EncBaseId.value).toEqual(0);
		});

		test("mdtTypeRef", () => {
			const d = pe.mdtTypeRef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.TypeRef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].ResolutionScope._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Namespace._sz).toEqual(2);

			expect(d.values[0].ResolutionScope.tid).toEqual(PE.MdTableIndex.AssemblyRef);
			expect(d.values[0].ResolutionScope.rid).toEqual(1);
			expect(d.values[0].Name.value).toEqual(1027);
			expect(d.values[0].Namespace.value).toEqual(1531);

			expect(d.values[3].ResolutionScope.tid).toEqual(PE.MdTableIndex.TypeRef);
			expect(d.values[3].ResolutionScope.rid).toEqual(3);
			expect(d.values[3].Name.value).toEqual(1619);
			expect(d.values[3].Namespace.value).toEqual(0);
		});

		test("mdtTypeDef", () => {
			const d = pe.mdtTypeDef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.TypeDef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Flags._sz).toEqual(4);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Namespace._sz).toEqual(2);
			expect(d.values[0].Extends._sz).toEqual(2);
			expect(d.values[0].FieldList._sz).toEqual(2);
			expect(d.values[0].MethodList._sz).toEqual(2);

			expect(d.values[0].Flags.value).toEqual(0);
			expect(d.values[0].Name.value).toEqual(324);
			expect(d.values[0].Namespace.value).toEqual(0);
			expect(d.values[0].Extends.tid).toEqual(2);
			expect(d.values[0].Extends.rid).toEqual(0);
			expect(d.values[0].FieldList.value).toEqual(1);
			expect(d.values[0].MethodList.value).toEqual(1);
		});

		test("mdtFieldPtr - Never appears", () => {
			const d = pe.mdtFieldPtr;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.FieldPtr]);
			expect(d._sz).toEqual(0);
		});

		test("mdtField", () => {
			const d = pe.mdtField;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Field]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Flags._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Signature._sz).toEqual(2);

			expect(d.values[0].Flags.value).toEqual(PE.CorFieldAttr.fa_Public | PE.CorFieldAttr.Static);
			expect(d.values[0].Name.value).toEqual(435);
			expect(d.values[0].Signature.value).toEqual(427);
		});

		test("mdtMethodPtr - Never appears", () => {
			const d = pe.mdtMethodPtr;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.MethodPtr]);
			expect(d._sz).toEqual(0);
		});

		test("mdtMethodDef", () => {
			const d = pe.mdtMethodDef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.MethodDef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].RVA._sz).toEqual(4);
			expect(d.values[0].ImplFlags._sz).toEqual(2);
			expect(d.values[0].Flags._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Signature._sz).toEqual(2);
			expect(d.values[0].ParamList._sz).toEqual(2);

			expect(d.values[0].RVA.value).toEqual(8272);
			expect(d.values[0].ImplFlags.value).toEqual(0);
			expect(d.values[0].Flags.value).toEqual(
				PE.CorMethodAttr.SpecialName |
				PE.CorMethodAttr.HideBySig |
				PE.CorMethodAttr.ma_Public);
			expect(d.values[0].Name.value).toEqual(67);
			expect(d.values[0].Signature.value).toEqual(499);
			expect(d.values[0].ParamList.value).toEqual(1);
		});

		test("mdtParamPtr - Never appears", () => {
			const d = pe.mdtParamPtr;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ParamPtr]);
			expect(d._sz).toEqual(0);
		});

		test("mdtParam", () => {
			const d = pe.mdtParam;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Param]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Flags._sz).toEqual(2);
			expect(d.values[0].Sequence._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);

			expect(d.values[0].Flags.value).toEqual(0);
			expect(d.values[0].Sequence.value).toEqual(1);
			expect(d.values[0].Name.value).toEqual(1100);
		});

		test("mdtInterfaceImpl", () => {
			const d = pe.mdtInterfaceImpl;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.InterfaceImpl]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Class._sz).toEqual(2);
			expect(d.values[0].Interface._sz).toEqual(2);

			expect(d.values[0].Class.value).toEqual(5);
			expect(d.values[0].Interface.tid).toEqual(PE.MdTableIndex.TypeDef);
			expect(d.values[0].Interface.rid).toEqual(3);
		});

		test("mdtMemberRef", () => {
			const d = pe.mdtMemberRef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.MemberRef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Class._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Signature._sz).toEqual(2);

			expect(d.values[0].Class.tid).toEqual(PE.MdTableIndex.TypeRef);
			expect(d.values[0].Class.rid).toEqual(1);
			expect(d.values[0].Name.value).toEqual(1467);
			expect(d.values[0].Signature.value).toEqual(1);
		});

		test("mdtConstant", () => {
			const d = pe.mdtConstant;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Constant]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Type._sz).toEqual(1);
			expect(d.values[0].PaddingZero._sz).toEqual(1);
			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].Value._sz).toEqual(2);

			expect(d.values[0].Type.value).toEqual(PE.CorElementType.I4);
			expect(d.values[0].PaddingZero.value).toEqual(0);
			expect(d.values[0].Parent.tid).toEqual(PE.MdTableIndex.Field);
			expect(d.values[0].Parent.rid).toEqual(5);
			expect(d.values[0].Value.value).toEqual(236);
		});

		test("mdtCustomAttribute", () => {
			const d = pe.mdtCustomAttribute;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.CustomAttribute]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].Type._sz).toEqual(2);
			expect(d.values[0].Value._sz).toEqual(2);

			expect(d.values[0].Parent.tid).toEqual(PE.MdTableIndex.MethodDef);
			expect(d.values[0].Parent.rid).toEqual(1);
			expect(d.values[0].Type.tid).toEqual(PE.MdTableIndex.MemberRef);
			expect(d.values[0].Type.rid).toEqual(4);
			expect(d.values[0].Value.value).toEqual(236);
		});

		test("mdtFieldMarshal", () => {
			const d = pe.mdtFieldMarshal;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.FieldMarshal]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].NativeType._sz).toEqual(2);

			expect(d.values[0].Parent.tid).toEqual(PE.MdTableIndex.Param);
			expect(d.values[0].Parent.rid).toEqual(7);
			expect(d.values[0].NativeType.value).toEqual(425);
		});

		test("mdtDeclSecurity", () => {
			const d = pe.mdtDeclSecurity;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.DeclSecurity]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Action._sz).toEqual(2);
			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].PermissionSet._sz).toEqual(2);

			expect(d.values[0].Action.value).toEqual(PE.CorDeclSecurity.Demand);
			expect(d.values[0].Parent.tid).toEqual(PE.MdTableIndex.MethodDef);
			expect(d.values[0].Parent.rid).toEqual(16);
			expect(d.values[0].PermissionSet.value).toEqual(280);
		});

		test("mdtClassLayout", () => {
			const d = pe.mdtClassLayout;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ClassLayout]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].PackingSize._sz).toEqual(2);
			expect(d.values[0].ClassSize._sz).toEqual(4);
			expect(d.values[0].Parent._sz).toEqual(2);

			expect(d.values[0].PackingSize.value).toEqual(8);
			expect(d.values[0].ClassSize.value).toEqual(8);
			expect(d.values[0].Parent.value).toEqual(7);
		});

		test("mdtFieldLayout", () => {
			const d = pe.mdtFieldLayout;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.FieldLayout]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].OffSet._sz).toEqual(4);
			expect(d.values[0].Field._sz).toEqual(2);

			expect(d.values[0].OffSet.value).toEqual(0);
			expect(d.values[0].Field.value).toEqual(15);
		});

		test("mdtStandAloneSig", () => {
			const d = pe.mdtStandAloneSig;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.StandAloneSig]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Signature._sz).toEqual(2);

			expect(d.values[0].Signature.value).toEqual(35);
		});

		test("mdtEventMap", () => {
			const d = pe.mdtEventMap;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.EventMap]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].EventList._sz).toEqual(2);

			expect(d.values[0].Parent.value).toEqual(2);
			expect(d.values[0].EventList.value).toEqual(1);
		});

		test("mdtEventPtr - Never appears", () => {
			const d = pe.mdtEventPtr;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.EventPtr]);
			expect(d._sz).toEqual(0);
		});

		test("mdtEvent", () => {
			const d = pe.mdtEvent;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Event]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].EventFlags._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].EventType._sz).toEqual(2);

			expect(d.values[0].EventFlags.value).toEqual(0);
			expect(d.values[0].Name.value).toEqual(109);
			expect(d.values[0].EventType.tid).toEqual(PE.MdTableIndex.TypeRef);
			expect(d.values[0].EventType.rid).toEqual(6);
		});

		test("mdtPropertyMap", () => {
			const d = pe.mdtPropertyMap;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.PropertyMap]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Parent._sz).toEqual(2);
			expect(d.values[0].PropertyList._sz).toEqual(2);

			expect(d.values[0].Parent.value).toEqual(2);
			expect(d.values[0].PropertyList.value).toEqual(1);
		});

		test("mdtPropertyPtr - Never appears", () => {
			const d = pe.mdtPropertyPtr;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.PropertyPtr]);
			expect(d._sz).toEqual(0);
		});

		test("mdtProperty", () => {
			const d = pe.mdtProperty;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Property]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].PropFlags._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Type._sz).toEqual(2);

			expect(d.values[0].PropFlags.value).toEqual(0);
			expect(d.values[0].Name.value).toEqual(1977);
			expect(d.values[0].Type.value).toEqual(578);
		});

		test("mdtMethodSemantics", () => {
			const d = pe.mdtMethodSemantics;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.MethodSemantics]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Semantic._sz).toEqual(2);
			expect(d.values[0].Method._sz).toEqual(2);
			expect(d.values[0].Association._sz).toEqual(2);

			expect(d.values[0].Semantic.value).toEqual(PE.CorMethodSemanticsAttr.AddOn);
			expect(d.values[0].Method.value).toEqual(1);
			expect(d.values[0].Association.tid).toEqual(PE.MdTableIndex.Event);
			expect(d.values[0].Association.rid).toEqual(1);
		});

		test("mdtMethodImpl", () => {
			const d = pe.mdtMethodImpl;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.MethodImpl]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Class._sz).toEqual(2);
			expect(d.values[0].MethodBody._sz).toEqual(2);
			expect(d.values[0].MethodDeclaration._sz).toEqual(2);

			expect(d.values[0].Class.value).toEqual(5);
			expect(d.values[0].MethodBody.tid).toEqual(PE.MdTableIndex.MethodDef);
			expect(d.values[0].MethodBody.rid).toEqual(24);
			expect(d.values[0].MethodDeclaration.tid).toEqual(PE.MdTableIndex.MethodDef);
			expect(d.values[0].MethodDeclaration.rid).toEqual(22);
		});

		test("mdtModuleRef", () => {
			const d = pe.mdtModuleRef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ModuleRef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Name._sz).toEqual(2);

			expect(d.values[0].Name.value).toEqual(1206);
		});

		test("mdtTypeSpec", () => {
			const d = pe.mdtTypeSpec;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.TypeSpec]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].Signature._sz).toEqual(2);

			expect(d.values[0].Signature.value).toEqual(16);
		});

		test("mdtImplMap", () => {
			const d = pe.mdtImplMap;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ImplMap]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].MappingFlags._sz).toEqual(2);
			expect(d.values[0].MemberForwarded._sz).toEqual(2);
			expect(d.values[0].ImportName._sz).toEqual(2);
			expect(d.values[0].ImportScope._sz).toEqual(2);

			expect(d.values[0].MappingFlags.value).toEqual(PE.CorPinvokeMap.cc_CallConvWinapi);
			expect(d.values[0].MemberForwarded.tid).toEqual(PE.MdTableIndex.MethodDef);
			expect(d.values[0].MemberForwarded.rid).toEqual(11);
			expect(d.values[0].ImportName.value).toEqual(1419);
			expect(d.values[0].ImportScope.value).toEqual(1);
		});

		test("mdtFieldRVA", () => {
			const d = peFieldRVA.mdtFieldRVA;

			expect(d.values.length).toEqual(peFieldRVA.mdTableRows[PE.MdTableIndex.FieldRVA]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].RVA._sz).toEqual(4);
			expect(d.values[0].Field._sz).toEqual(2);

			expect(d.values[0].RVA.value).toEqual(16384);
			expect(d.values[0].Field.value).toEqual(1);
		});

		test("mdtENCLog - Never appears", () => {
			const d = pe.mdtENCLog;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ENCLog]);
			expect(d._sz).toEqual(0);
		});

		test("mdtENCMap - Never appears", () => {
			const d = pe.mdtENCMap;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.ENCMap]);
			expect(d._sz).toEqual(0);
		});

		test("mdtAssembly", () => {
			const d = pe.mdtAssembly;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.Assembly]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].HashAlgId._sz).toEqual(4);
			expect(d.values[0].MajorVersion._sz).toEqual(2);
			expect(d.values[0].MinorVersion._sz).toEqual(2);
			expect(d.values[0].BuildNumber._sz).toEqual(2);
			expect(d.values[0].RevisionNumber._sz).toEqual(2);
			expect(d.values[0].Flags._sz).toEqual(4);
			expect(d.values[0].PublicKey._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Locale._sz).toEqual(2);

			expect(d.values[0].HashAlgId.value).toEqual(PE.AssemblyHashAlgorithm.SHA1);
			expect(d.values[0].MajorVersion.value).toEqual(1);
			expect(d.values[0].MinorVersion.value).toEqual(2);
			expect(d.values[0].BuildNumber.value).toEqual(3);
			expect(d.values[0].RevisionNumber.value).toEqual(4);
			expect(d.values[0].Flags.value).toEqual(0);
			expect(d.values[0].PublicKey.value).toEqual(0);
			expect(d.values[0].Name.value).toEqual(1860);
			expect(d.values[0].Locale.value).toEqual(0);
		});

		test("mdtAssemblyProcessor - Never appears", () => {
			const d = pe.mdtAssemblyProcessor;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.AssemblyProcessor]);
			expect(d._sz).toEqual(0);
		});

		test("mdtAssemblyOS - Never appears", () => {
			const d = pe.mdtAssemblyOS;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.AssemblyOS]);
			expect(d._sz).toEqual(0);
		});

		test("mdtAssemblyRef", () => {
			const d = pe.mdtAssemblyRef;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.AssemblyRef]);
			expect(d._sz).toEqual(d.values[0]._sz * d.values.length);

			expect(d.values[0].MajorVersion._sz).toEqual(2);
			expect(d.values[0].MinorVersion._sz).toEqual(2);
			expect(d.values[0].BuildNumber._sz).toEqual(2);
			expect(d.values[0].RevisionNumber._sz).toEqual(2);
			expect(d.values[0].Flags._sz).toEqual(4);
			expect(d.values[0].PublicKeyOrToken._sz).toEqual(2);
			expect(d.values[0].Name._sz).toEqual(2);
			expect(d.values[0].Locale._sz).toEqual(2);
			expect(d.values[0].HashValue._sz).toEqual(2);

			expect(d.values[0].MajorVersion.value).toEqual(4);
			expect(d.values[0].MinorVersion.value).toEqual(0);
			expect(d.values[0].BuildNumber.value).toEqual(0);
			expect(d.values[0].RevisionNumber.value).toEqual(0);
			expect(d.values[0].Flags.value).toEqual(0);
			expect(d.values[0].PublicKeyOrToken.value).toEqual(227);
			expect(d.values[0].Name.value).toEqual(369);
			expect(d.values[0].Locale.value).toEqual(0);
			expect(d.values[0].HashValue.value).toEqual(0);
		});

		test("mdtAssemblyRefProcessor - Never appears", () => {
			const d = pe.mdtAssemblyRefProcessor;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.AssemblyRefProcessor]);
			expect(d._sz).toEqual(0);
		});

		test("mdtAssemblyRefOS - Never appears", () => {
			const d = pe.mdtAssemblyRefOS;

			expect(d.values.length).toEqual(pe.mdTableRows[PE.MdTableIndex.AssemblyRefOS]);
			expect(d._sz).toEqual(0);
		});

		test("mdtFile", () => {
			const d = pe.mdtFile;

			expect(d).toEqual({
				"_off": 3234, "_sz": 8, "values": [{
					"_off": 3234, "_sz": 8,
					"Flags": { "_off": 3234, "_sz": 4, "value": 0 },
					"Name": { "_off": 3238, "_sz": 2, "value": 761 },
					"HashValue": { "_off": 3240, "_sz": 2, "value": 478 }
				}]
			});
		});

		test("mdtExportedType", () => {
			const d = pe.mdtExportedType;

			expect(d).toEqual({
				"_off": 3242, "_sz": 14, "values": [{
					"_off": 3242, "_sz": 14,
					"Flags": { "_off": 3242, "_sz": 4, "value": 1 },
					"TypeDefId": { "_off": 3246, "_sz": 4, "value": 33554434 },
					"TypeName": { "_off": 3250, "_sz": 2, "value": 820 },
					"TypeNamespace": { "_off": 3252, "_sz": 2, "value": 1634 },
					"Implementation": { "_off": 3254, "_sz": 2, "tid": 38, "rid": 1 }
				}]
			});
		});

		test("mdtManifestResource", () => {
			const d = pe.mdtManifestResource;

			expect(d).toEqual({
				"_off": 3256, "_sz": 12, "values": [{
					"_off": 3256, "_sz": 12,
					"Offset": { "_off": 3256, "_sz": 4, "value": 0 },
					"Flags": { "_off": 3260, "_sz": 4, "value": 1 },
					"Name": { "_off": 3264, "_sz": 2, "value": 1580 },
					"Implementation": { "_off": 3266, "_sz": 2, "tid": 38, "rid": 0 }
				}]
			});
		});

		test("mdtNestedClass", () => {
			const d = pe.mdtNestedClass;

			expect(d).toEqual({
				"_off": 3268, "_sz": 8, "values": [{
					"_off": 3268, "_sz": 4,
					"NestedClass": { "_off": 3268, "_sz": 2, "value": 11 },
					"EnclosingClass": { "_off": 3270, "_sz": 2, "value": 2 }
				}, {
					"_off": 3272, "_sz": 4,
					"NestedClass": { "_off": 3272, "_sz": 2, "value": 12 },
					"EnclosingClass": { "_off": 3274, "_sz": 2, "value": 2 }
				}]
			});
		});

		test("mdtGenericParam", () => {
			const d = pe.mdtGenericParam;

			expect(d).toEqual({
				"_off": 3276, "_sz": 32, "values": [{
					"_off": 3276, "_sz": 8,
					"Number": { "_off": 3276, "_sz": 2, "value": 0 },
					"Flags": { "_off": 3278, "_sz": 2, "value": 16 },
					"Owner": { "_off": 3280, "_sz": 2, "tid": 2, "rid": 10 },
					"Name": { "_off": 3282, "_sz": 2, "value": 1278 }
				}, {
					"_off": 3284, "_sz": 8,
					"Number": { "_off": 3284, "_sz": 2, "value": 1 },
					"Flags": { "_off": 3286, "_sz": 2, "value": 16 },
					"Owner": { "_off": 3288, "_sz": 2, "tid": 2, "rid": 10 },
					"Name": { "_off": 3290, "_sz": 2, "value": 1447 }
				}, {
					"_off": 3292, "_sz": 8,
					"Number": { "_off": 3292, "_sz": 2, "value": 0 },
					"Flags": { "_off": 3294, "_sz": 2, "value": 0 },
					"Owner": { "_off": 3296, "_sz": 2, "tid": 6, "rid": 17 },
					"Name": { "_off": 3298, "_sz": 2, "value": 1852 }
				}, {
					"_off": 3300, "_sz": 8,
					"Number": { "_off": 3300, "_sz": 2, "value": 1 },
					"Flags": { "_off": 3302, "_sz": 2, "value": 16 },
					"Owner": { "_off": 3304, "_sz": 2, "tid": 6, "rid": 17 },
					"Name": { "_off": 3306, "_sz": 2, "value": 1839 }
				}]
			});
		});

		test("mdtMethodSpec", () => {
			const d = pe.mdtMethodSpec;

			expect(d).toEqual({
				"_off": 3308, "_sz": 12, "values": [{
					"_off": 3308, "_sz": 4,
					"Method": { "_off": 3308, "_sz": 2, "tid": 10, "rid": 8 },
					"Instantiation": { "_off": 3310, "_sz": 2, "value": 66 }
				}, {
					"_off": 3312, "_sz": 4,
					"Method": { "_off": 3312, "_sz": 2, "tid": 10, "rid": 8 },
					"Instantiation": { "_off": 3314, "_sz": 2, "value": 105 }
				}, {
					"_off": 3316, "_sz": 4,
					"Method": { "_off": 3316, "_sz": 2, "tid": 6, "rid": 17 },
					"Instantiation": { "_off": 3318, "_sz": 2, "value": 207 }
				}]
			});
		});

		test("mdtGenericParamConstraint", () => {
			const d = pe.mdtGenericParamConstraint;

			expect(d).toEqual({
				"_off": 3320, "_sz": 8, "values": [{
					"_off": 3320, "_sz": 4,
					"Owner": { "_off": 3320, "_sz": 2, "value": 1 },
					"Constraint": { "_off": 3322, "_sz": 2, "tid": 2, "rid": 2 }
				}, {
					"_off": 3324, "_sz": 4,
					"Owner": { "_off": 3324, "_sz": 2, "value": 3 },
					"Constraint": { "_off": 3326, "_sz": 2, "tid": 2, "rid": 2 }
				}]
			});
		});
	});

	describe("PeError", () => {
		const pe32 = TestCases.load("Simple.X86.exe__");
		const pe64 = TestCases.load("Simple.X64.exe__");

		test("FileTooShort", () => {
			expectPeError(PE.PeErrorType.FileTooShort, () => {
				const buf = new ArrayBuffer(1);
				const pe = PE.load(buf);
			});
		});

		test("FileTooLong", () => {
			expectPeError(PE.PeErrorType.FileTooLong, () => {
				const buf = new ArrayBuffer(2.1 * 1024 * 1024 * 1024);
				const pe = PE.load(buf);
			});
		});

		test("InvalidOffset", () => {
			expectPeError(PE.PeErrorType.InvalidOffset, () => {
				let buf = pe32.data.buffer.slice(0, 0x80 + 4);
				let ab = new Uint8Array(buf);
				const pe = PE.load(buf);
			});
		});

		test("InvalidSize", () => {
			expectPeError(PE.PeErrorType.InvalidSize, () => {
				let buf = pe32.data.buffer.slice(0, 0x80 + 5);
				let ab = new Uint8Array(buf);
				const pe = PE.load(buf);
			});
		});

		test("InvalidFilePointer", () => {
			expectPeError(PE.PeErrorType.InvalidFilePointer, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.dosHeader.e_lfanew._off] = 0xFF;
				ab[pe32.dosHeader.e_lfanew._off + 1] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidDosSignature", () => {
			expectPeError(PE.PeErrorType.InvalidDosSignature, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[0] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidPeSignature", () => {
			expectPeError(PE.PeErrorType.InvalidPeSignature, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.peSignature._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidSizeOfOptionalHeader - 32", () => {
			expectPeError(PE.PeErrorType.InvalidSizeOfOptionalHeader, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.fileHeader.SizeOfOptionalHeader._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidSizeOfOptionalHeader - 64", () => {
			expectPeError(PE.PeErrorType.InvalidSizeOfOptionalHeader, () => {
				let buf = pe64.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe64.fileHeader.SizeOfOptionalHeader._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidOptionalHeaderMagic - 32", () => {
			expectPeError(PE.PeErrorType.InvalidOptionalHeaderMagic, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.optionalHeader._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidOptionalHeaderMagic - 64", () => {
			expectPeError(PE.PeErrorType.InvalidOptionalHeaderMagic, () => {
				let buf = pe64.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe64.optionalHeader._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidNumberOfDataDirectories - 32", () => {
			expectPeError(PE.PeErrorType.InvalidNumberOfDataDirectories, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.optionalHeader.NumberOfRvaAndSizes._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidNumberOfDataDirectories - 64", () => {
			expectPeError(PE.PeErrorType.InvalidNumberOfDataDirectories, () => {
				let buf = pe64.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe64.optionalHeader.NumberOfRvaAndSizes._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidSizeOfCliHeader", () => {
			expectPeError(PE.PeErrorType.InvalidSizeOfCliHeader, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.cliHeader.cb._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});

		test("InvalidMdSignature", () => {
			expectPeError(PE.PeErrorType.InvalidMdSignature, () => {
				let buf = pe32.data.buffer.slice(0);
				let ab = new Uint8Array(buf);
				ab[pe32.mdRoot.Signature._off] = 0xFF;
				const pe = PE.load(buf);
			});
		});
	});
});
