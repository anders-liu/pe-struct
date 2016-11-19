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
		const peFullMD = TestCases.load("FullMetadataTables.Assembly.exe__");
		const peFrva = TestCases.load("FieldRva.exe__");
		const peSigned = TestCases.load("Simple.Signed.exe__");

		test("cliHeader", () => {
			const d = pe32.cliHeader;

			expect(d.cb.value).toEqual(d._sz);

			expect(d.MetaData.Rva.value).toBeGreaterThan(0);
			expect(d.MetaData.Size.value).toBeGreaterThan(0);

			expect(d._off).toEqual(0x208);
			expect(d._sz).toEqual(72);
		});

		test("ManRes", () => {
			const d = peFullMD.ManRes;
			expect(d).toEqual({
				"_off": 6188, "_sz": 240,
				"values": [{
					"_off": 6188, "_sz": 236,
					"Size": { "_off": 6188, "_sz": 4, "value": 230 },
					"Data": { "_off": 6192, "_sz": 230 },
					"Padding": { "_off": 6422, "_sz": 2 }
				}, {
					"_off": 6424, "_sz": 4,
					"Size": { "_off": 6424, "_sz": 4, "value": 0 },
					"Data": { "_off": 6428, "_sz": 0 },
					"Padding": { "_off": 6428, "_sz": 0 }
				}]
			});
		});

		test("SNSignature", () => {
			const d = peSigned.SNSignature;
			expect(d).toEqual({ "_off": 1560, "_sz": 128 });

			const a = peSigned.mdtAssembly.values[0];
			const blobPos = a.PublicKey.value + peSigned.mdsBlob._off;
			const b = peSigned.mdsBlob.values.filter(d => d._off == blobPos);

			expect(b[0].data).toEqual({ "_off": 1344, "_sz": 160 });
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
			const d = peFullMD.mdTableHeader;

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
			const d = peFullMD.mdTableRows;
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

	describe("IL", () => {
		const peFullMD = TestCases.load("FullMetadataTables.Assembly.exe__");
		const peFullIL = TestCases.load("FullIL.exe__");
		const peEH = TestCases.load("ExceptionHandling.exe__");

		test("ILMethodHeaderTiny", () => {
			const mr = peFullMD.mdtMethodDef.values[12];
			const m = PE.loadIL(peFullMD, mr);
			expect(m.Header).toEqual({
				"_off": 1069, "_sz": 1,
				"flagsValue": 2,
				"codeSizeValue": 12,
				"FlagsAndCodeSize": { "_off": 1069, "_sz": 1, "value": 50 },
			});
		});

		test("ILMethodHeaderFat", () => {
			const mr = peFullMD.mdtMethodDef.values[11];
			const m = PE.loadIL(peFullMD, mr);
			expect(m.Header).toEqual({
				"_off": 944, "_sz": 12,
				"flagsValue": 12307,
				"codeSizeValue": 113,
				"Flags": { "_off": 944, "_sz": 2, "value": 12307 },
				"MaxStack": { "_off": 946, "_sz": 2, "value": 2 },
				"CodeSize": { "_off": 948, "_sz": 4, "value": 113 },
				"LocalVariableSignature": { "_off": 952, "_sz": 4, "tid": 17, "rid": 5 }
			});
		});

		test("ILMethod.Body", () => {
			const mr = peFullIL.mdtMethodDef.values[0];
			const m = PE.loadIL(peFullIL, mr);
			expect(m.Body).toEqual({
				"_off": 604, "_sz": 503, "values": [{
					"_off": 604, "_sz": 1, "opcode": { "_off": 604, "_sz": 1, "value": 0 }
				}, {
					"_off": 605, "_sz": 1, "opcode": { "_off": 605, "_sz": 1, "value": 1 }
				}, {
					"_off": 606, "_sz": 1, "opcode": { "_off": 606, "_sz": 1, "value": 2 }
				}, {
					"_off": 607, "_sz": 1, "opcode": { "_off": 607, "_sz": 1, "value": 3 }
				}, {
					"_off": 608, "_sz": 1, "opcode": { "_off": 608, "_sz": 1, "value": 4 }
				}, {
					"_off": 609, "_sz": 1, "opcode": { "_off": 609, "_sz": 1, "value": 5 }
				}, {
					"_off": 610, "_sz": 1, "opcode": { "_off": 610, "_sz": 1, "value": 6 }
				}, {
					"_off": 611, "_sz": 1, "opcode": { "_off": 611, "_sz": 1, "value": 7 }
				}, {
					"_off": 612, "_sz": 1, "opcode": { "_off": 612, "_sz": 1, "value": 8 }
				}, {
					"_off": 613, "_sz": 1, "opcode": { "_off": 613, "_sz": 1, "value": 9 }
				}, {
					"_off": 614, "_sz": 1, "opcode": { "_off": 614, "_sz": 1, "value": 10 }
				}, {
					"_off": 615, "_sz": 1, "opcode": { "_off": 615, "_sz": 1, "value": 11 }
				}, {
					"_off": 616, "_sz": 1, "opcode": { "_off": 616, "_sz": 1, "value": 12 }
				}, {
					"_off": 617, "_sz": 1, "opcode": { "_off": 617, "_sz": 1, "value": 13 }
				}, {
					"_off": 618, "_sz": 2, "opcode": { "_off": 618, "_sz": 1, "value": 14 },
					"oprand": { "_off": 619, "_sz": 1, "value": 14 }
				}, {
					"_off": 620, "_sz": 2, "opcode": { "_off": 620, "_sz": 1, "value": 15 },
					"oprand": { "_off": 621, "_sz": 1, "value": 15 }
				}, {
					"_off": 622, "_sz": 2, "opcode": { "_off": 622, "_sz": 1, "value": 16 },
					"oprand": { "_off": 623, "_sz": 1, "value": 16 }
				}, {
					"_off": 624, "_sz": 2, "opcode": { "_off": 624, "_sz": 1, "value": 17 },
					"oprand": { "_off": 625, "_sz": 1, "value": 17 }
				}, {
					"_off": 626, "_sz": 2, "opcode": { "_off": 626, "_sz": 1, "value": 18 },
					"oprand": { "_off": 627, "_sz": 1, "value": 18 }
				}, {
					"_off": 628, "_sz": 2, "opcode": { "_off": 628, "_sz": 1, "value": 19 },
					"oprand": { "_off": 629, "_sz": 1, "value": 19 }
				}, {
					"_off": 630, "_sz": 1, "opcode": { "_off": 630, "_sz": 1, "value": 20 }
				}, {
					"_off": 631, "_sz": 1, "opcode": { "_off": 631, "_sz": 1, "value": 21 }
				}, {
					"_off": 632, "_sz": 1, "opcode": { "_off": 632, "_sz": 1, "value": 22 }
				}, {
					"_off": 633, "_sz": 1, "opcode": { "_off": 633, "_sz": 1, "value": 23 }
				}, {
					"_off": 634, "_sz": 1, "opcode": { "_off": 634, "_sz": 1, "value": 24 }
				}, {
					"_off": 635, "_sz": 1, "opcode": { "_off": 635, "_sz": 1, "value": 25 }
				}, {
					"_off": 636, "_sz": 1, "opcode": { "_off": 636, "_sz": 1, "value": 26 }
				}, {
					"_off": 637, "_sz": 1, "opcode": { "_off": 637, "_sz": 1, "value": 27 }
				}, {
					"_off": 638, "_sz": 1, "opcode": { "_off": 638, "_sz": 1, "value": 28 }
				}, {
					"_off": 639, "_sz": 1, "opcode": { "_off": 639, "_sz": 1, "value": 29 }
				}, {
					"_off": 640, "_sz": 1, "opcode": { "_off": 640, "_sz": 1, "value": 30 }
				}, {
					"_off": 641, "_sz": 2, "opcode": { "_off": 641, "_sz": 1, "value": 31 },
					"oprand": { "_off": 642, "_sz": 1, "value": -31 }
				}, {
					"_off": 643, "_sz": 5, "opcode": { "_off": 643, "_sz": 1, "value": 32 },
					"oprand": { "_off": 644, "_sz": 4, "value": -32 }
				}, {
					"_off": 648, "_sz": 9, "opcode": { "_off": 648, "_sz": 1, "value": 33 },
					"oprand": { "_off": 649, "_sz": 8, "low": 4294967263, "high": 4294967295 }
				}, {
					"_off": 657, "_sz": 5, "opcode": { "_off": 657, "_sz": 1, "value": 34 },
					"oprand": { "_off": 658, "_sz": 4, "value": 34.34000015258789 }
				}, {
					"_off": 662, "_sz": 9, "opcode": { "_off": 662, "_sz": 1, "value": 35 },
					"oprand": { "_off": 663, "_sz": 8, "value": 35.35 }
				}, {
					"_off": 671, "_sz": 1, "opcode": { "_off": 671, "_sz": 1, "value": 37 }
				}, {
					"_off": 672, "_sz": 1, "opcode": { "_off": 672, "_sz": 1, "value": 38 }
				}, {
					"_off": 673, "_sz": 5, "opcode": { "_off": 673, "_sz": 1, "value": 39 },
					"oprand": { "_off": 674, "_sz": 4, "tid": 10, "rid": 1 }
				}, {
					"_off": 678, "_sz": 5, "opcode": { "_off": 678, "_sz": 1, "value": 40 },
					"oprand": { "_off": 679, "_sz": 4, "tid": 10, "rid": 1 }
				}, {
					"_off": 683, "_sz": 5, "opcode": { "_off": 683, "_sz": 1, "value": 41 },
					"oprand": { "_off": 684, "_sz": 4, "tid": 17, "rid": 1 }
				}, {
					"_off": 688, "_sz": 1, "opcode": { "_off": 688, "_sz": 1, "value": 42 }
				}, {
					"_off": 689, "_sz": 2, "opcode": { "_off": 689, "_sz": 1, "value": 43 },
					"oprand": { "_off": 690, "_sz": 1, "value": -3 }
				}, {
					"_off": 691, "_sz": 2, "opcode": { "_off": 691, "_sz": 1, "value": 44 },
					"oprand": { "_off": 692, "_sz": 1, "value": -5 }
				}, {
					"_off": 693, "_sz": 2, "opcode": { "_off": 693, "_sz": 1, "value": 45 },
					"oprand": { "_off": 694, "_sz": 1, "value": -7 }
				}, {
					"_off": 695, "_sz": 2, "opcode": { "_off": 695, "_sz": 1, "value": 46 },
					"oprand": { "_off": 696, "_sz": 1, "value": -9 }
				}, {
					"_off": 697, "_sz": 2, "opcode": { "_off": 697, "_sz": 1, "value": 47 },
					"oprand": { "_off": 698, "_sz": 1, "value": -11 }
				}, {
					"_off": 699, "_sz": 2, "opcode": { "_off": 699, "_sz": 1, "value": 48 },
					"oprand": { "_off": 700, "_sz": 1, "value": -13 }
				}, {
					"_off": 701, "_sz": 2, "opcode": { "_off": 701, "_sz": 1, "value": 49 },
					"oprand": { "_off": 702, "_sz": 1, "value": -15 }
				}, {
					"_off": 703, "_sz": 2, "opcode": { "_off": 703, "_sz": 1, "value": 50 },
					"oprand": { "_off": 704, "_sz": 1, "value": -17 }
				}, {
					"_off": 705, "_sz": 2, "opcode": { "_off": 705, "_sz": 1, "value": 51 },
					"oprand": { "_off": 706, "_sz": 1, "value": -19 }
				}, {
					"_off": 707, "_sz": 2, "opcode": { "_off": 707, "_sz": 1, "value": 52 },
					"oprand": { "_off": 708, "_sz": 1, "value": -21 }
				}, {
					"_off": 709, "_sz": 2, "opcode": { "_off": 709, "_sz": 1, "value": 53 },
					"oprand": { "_off": 710, "_sz": 1, "value": -23 }
				}, {
					"_off": 711, "_sz": 2, "opcode": { "_off": 711, "_sz": 1, "value": 54 },
					"oprand": { "_off": 712, "_sz": 1, "value": -25 }
				}, {
					"_off": 713, "_sz": 2, "opcode": { "_off": 713, "_sz": 1, "value": 55 },
					"oprand": { "_off": 714, "_sz": 1, "value": -27 }
				}, {
					"_off": 715, "_sz": 5, "opcode": { "_off": 715, "_sz": 1, "value": 56 },
					"oprand": { "_off": 716, "_sz": 4, "value": -116 }
				}, {
					"_off": 720, "_sz": 5, "opcode": { "_off": 720, "_sz": 1, "value": 57 },
					"oprand": { "_off": 721, "_sz": 4, "value": -121 }
				}, {
					"_off": 725, "_sz": 5, "opcode": { "_off": 725, "_sz": 1, "value": 58 },
					"oprand": { "_off": 726, "_sz": 4, "value": -126 }
				}, {
					"_off": 730, "_sz": 5, "opcode": { "_off": 730, "_sz": 1, "value": 59 },
					"oprand": { "_off": 731, "_sz": 4, "value": -131 }
				}, {
					"_off": 735, "_sz": 5, "opcode": { "_off": 735, "_sz": 1, "value": 60 },
					"oprand": { "_off": 736, "_sz": 4, "value": -136 }
				}, {
					"_off": 740, "_sz": 5, "opcode": { "_off": 740, "_sz": 1, "value": 61 },
					"oprand": { "_off": 741, "_sz": 4, "value": -141 }
				}, {
					"_off": 745, "_sz": 5, "opcode": { "_off": 745, "_sz": 1, "value": 62 },
					"oprand": { "_off": 746, "_sz": 4, "value": -146 }
				}, {
					"_off": 750, "_sz": 5, "opcode": { "_off": 750, "_sz": 1, "value": 63 },
					"oprand": { "_off": 751, "_sz": 4, "value": -151 }
				}, {
					"_off": 755, "_sz": 5, "opcode": { "_off": 755, "_sz": 1, "value": 64 },
					"oprand": { "_off": 756, "_sz": 4, "value": -156 }
				}, {
					"_off": 760, "_sz": 5, "opcode": { "_off": 760, "_sz": 1, "value": 65 },
					"oprand": { "_off": 761, "_sz": 4, "value": -161 }
				}, {
					"_off": 765, "_sz": 5, "opcode": { "_off": 765, "_sz": 1, "value": 66 },
					"oprand": { "_off": 766, "_sz": 4, "value": -166 }
				}, {
					"_off": 770, "_sz": 5, "opcode": { "_off": 770, "_sz": 1, "value": 67 },
					"oprand": { "_off": 771, "_sz": 4, "value": -171 }
				}, {
					"_off": 775, "_sz": 5, "opcode": { "_off": 775, "_sz": 1, "value": 68 },
					"oprand": { "_off": 776, "_sz": 4, "value": -176 }
				}, {
					"_off": 780, "_sz": 17, "opcode": { "_off": 780, "_sz": 1, "value": 69 },
					"oprand": { "_off": 781, "_sz": 16, "count": { "_off": 781, "_sz": 4, "value": 3 }, "targets": { "_off": 785, "_sz": 12, "values": [{ "_off": 785, "_sz": 4, "value": -193 }, { "_off": 789, "_sz": 4, "value": -109 }, { "_off": 793, "_sz": 4, "value": 310 }] } }
				}, {
					"_off": 797, "_sz": 1, "opcode": { "_off": 797, "_sz": 1, "value": 70 }
				}, {
					"_off": 798, "_sz": 1, "opcode": { "_off": 798, "_sz": 1, "value": 71 }
				}, {
					"_off": 799, "_sz": 1, "opcode": { "_off": 799, "_sz": 1, "value": 72 }
				}, {
					"_off": 800, "_sz": 1, "opcode": { "_off": 800, "_sz": 1, "value": 73 }
				}, {
					"_off": 801, "_sz": 1, "opcode": { "_off": 801, "_sz": 1, "value": 74 }
				}, {
					"_off": 802, "_sz": 1, "opcode": { "_off": 802, "_sz": 1, "value": 75 }
				}, {
					"_off": 803, "_sz": 1, "opcode": { "_off": 803, "_sz": 1, "value": 76 }
				}, {
					"_off": 804, "_sz": 1, "opcode": { "_off": 804, "_sz": 1, "value": 77 }
				}, {
					"_off": 805, "_sz": 1, "opcode": { "_off": 805, "_sz": 1, "value": 78 }
				}, {
					"_off": 806, "_sz": 1, "opcode": { "_off": 806, "_sz": 1, "value": 79 }
				}, {
					"_off": 807, "_sz": 1, "opcode": { "_off": 807, "_sz": 1, "value": 80 }
				}, {
					"_off": 808, "_sz": 1, "opcode": { "_off": 808, "_sz": 1, "value": 81 }
				}, {
					"_off": 809, "_sz": 1, "opcode": { "_off": 809, "_sz": 1, "value": 82 }
				}, {
					"_off": 810, "_sz": 1, "opcode": { "_off": 810, "_sz": 1, "value": 83 }
				}, {
					"_off": 811, "_sz": 1, "opcode": { "_off": 811, "_sz": 1, "value": 84 }
				}, {
					"_off": 812, "_sz": 1, "opcode": { "_off": 812, "_sz": 1, "value": 85 }
				}, {
					"_off": 813, "_sz": 1, "opcode": { "_off": 813, "_sz": 1, "value": 86 }
				}, {
					"_off": 814, "_sz": 1, "opcode": { "_off": 814, "_sz": 1, "value": 87 }
				}, {
					"_off": 815, "_sz": 1, "opcode": { "_off": 815, "_sz": 1, "value": 88 }
				}, {
					"_off": 816, "_sz": 1, "opcode": { "_off": 816, "_sz": 1, "value": 89 }
				}, {
					"_off": 817, "_sz": 1, "opcode": { "_off": 817, "_sz": 1, "value": 90 }
				}, {
					"_off": 818, "_sz": 1, "opcode": { "_off": 818, "_sz": 1, "value": 91 }
				}, {
					"_off": 819, "_sz": 1, "opcode": { "_off": 819, "_sz": 1, "value": 92 }
				}, {
					"_off": 820, "_sz": 1, "opcode": { "_off": 820, "_sz": 1, "value": 93 }
				}, {
					"_off": 821, "_sz": 1, "opcode": { "_off": 821, "_sz": 1, "value": 94 }
				}, {
					"_off": 822, "_sz": 1, "opcode": { "_off": 822, "_sz": 1, "value": 95 }
				}, {
					"_off": 823, "_sz": 1, "opcode": { "_off": 823, "_sz": 1, "value": 96 }
				}, {
					"_off": 824, "_sz": 1, "opcode": { "_off": 824, "_sz": 1, "value": 97 }
				}, {
					"_off": 825, "_sz": 1, "opcode": { "_off": 825, "_sz": 1, "value": 98 }
				}, {
					"_off": 826, "_sz": 1, "opcode": { "_off": 826, "_sz": 1, "value": 99 }
				}, {
					"_off": 827, "_sz": 1, "opcode": { "_off": 827, "_sz": 1, "value": 100 }
				}, {
					"_off": 828, "_sz": 1, "opcode": { "_off": 828, "_sz": 1, "value": 101 }
				}, {
					"_off": 829, "_sz": 1, "opcode": { "_off": 829, "_sz": 1, "value": 102 }
				}, {
					"_off": 830, "_sz": 1, "opcode": { "_off": 830, "_sz": 1, "value": 103 }
				}, {
					"_off": 831, "_sz": 1, "opcode": { "_off": 831, "_sz": 1, "value": 104 }
				}, {
					"_off": 832, "_sz": 1, "opcode": { "_off": 832, "_sz": 1, "value": 105 }
				}, {
					"_off": 833, "_sz": 1, "opcode": { "_off": 833, "_sz": 1, "value": 106 }
				}, {
					"_off": 834, "_sz": 1, "opcode": { "_off": 834, "_sz": 1, "value": 107 }
				}, {
					"_off": 835, "_sz": 1, "opcode": { "_off": 835, "_sz": 1, "value": 108 }
				}, {
					"_off": 836, "_sz": 1, "opcode": { "_off": 836, "_sz": 1, "value": 109 }
				}, {
					"_off": 837, "_sz": 1, "opcode": { "_off": 837, "_sz": 1, "value": 110 }
				}, {
					"_off": 838, "_sz": 5, "opcode": { "_off": 838, "_sz": 1, "value": 111 },
					"oprand": { "_off": 839, "_sz": 4, "tid": 10, "rid": 2 }
				}, {
					"_off": 843, "_sz": 5, "opcode": { "_off": 843, "_sz": 1, "value": 112 },
					"oprand": { "_off": 844, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 848, "_sz": 5, "opcode": { "_off": 848, "_sz": 1, "value": 113 },
					"oprand": { "_off": 849, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 853, "_sz": 5, "opcode": { "_off": 853, "_sz": 1, "value": 114 },
					"oprand": { "_off": 854, "_sz": 4, "tid": 112, "rid": 1 }
				}, {
					"_off": 858, "_sz": 5, "opcode": { "_off": 858, "_sz": 1, "value": 115 },
					"oprand": { "_off": 859, "_sz": 4, "tid": 10, "rid": 3 }
				}, {
					"_off": 863, "_sz": 5, "opcode": { "_off": 863, "_sz": 1, "value": 116 },
					"oprand": { "_off": 864, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 868, "_sz": 5, "opcode": { "_off": 868, "_sz": 1, "value": 117 },
					"oprand": { "_off": 869, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 873, "_sz": 1, "opcode": { "_off": 873, "_sz": 1, "value": 118 }
				}, {
					"_off": 874, "_sz": 5, "opcode": { "_off": 874, "_sz": 1, "value": 121 },
					"oprand": { "_off": 875, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 879, "_sz": 1, "opcode": { "_off": 879, "_sz": 1, "value": 122 }
				}, {
					"_off": 880, "_sz": 5, "opcode": { "_off": 880, "_sz": 1, "value": 123 },
					"oprand": { "_off": 881, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 885, "_sz": 5, "opcode": { "_off": 885, "_sz": 1, "value": 124 },
					"oprand": { "_off": 886, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 890, "_sz": 5, "opcode": { "_off": 890, "_sz": 1, "value": 125 },
					"oprand": { "_off": 891, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 895, "_sz": 5, "opcode": { "_off": 895, "_sz": 1, "value": 126 },
					"oprand": { "_off": 896, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 900, "_sz": 5, "opcode": { "_off": 900, "_sz": 1, "value": 127 },
					"oprand": { "_off": 901, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 905, "_sz": 5, "opcode": { "_off": 905, "_sz": 1, "value": 128 },
					"oprand": { "_off": 906, "_sz": 4, "tid": 10, "rid": 4 }
				}, {
					"_off": 910, "_sz": 5, "opcode": { "_off": 910, "_sz": 1, "value": 129 },
					"oprand": { "_off": 911, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 915, "_sz": 1, "opcode": { "_off": 915, "_sz": 1, "value": 130 }
				}, {
					"_off": 916, "_sz": 1, "opcode": { "_off": 916, "_sz": 1, "value": 131 }
				}, {
					"_off": 917, "_sz": 1, "opcode": { "_off": 917, "_sz": 1, "value": 132 }
				}, {
					"_off": 918, "_sz": 1, "opcode": { "_off": 918, "_sz": 1, "value": 133 }
				}, {
					"_off": 919, "_sz": 1, "opcode": { "_off": 919, "_sz": 1, "value": 134 }
				}, {
					"_off": 920, "_sz": 1, "opcode": { "_off": 920, "_sz": 1, "value": 135 }
				}, {
					"_off": 921, "_sz": 1, "opcode": { "_off": 921, "_sz": 1, "value": 136 }
				}, {
					"_off": 922, "_sz": 1, "opcode": { "_off": 922, "_sz": 1, "value": 137 }
				}, {
					"_off": 923, "_sz": 1, "opcode": { "_off": 923, "_sz": 1, "value": 138 }
				}, {
					"_off": 924, "_sz": 1, "opcode": { "_off": 924, "_sz": 1, "value": 139 }
				}, {
					"_off": 925, "_sz": 5, "opcode": { "_off": 925, "_sz": 1, "value": 140 },
					"oprand": { "_off": 926, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 930, "_sz": 5, "opcode": { "_off": 930, "_sz": 1, "value": 141 },
					"oprand": { "_off": 931, "_sz": 4, "tid": 1, "rid": 1 }
				}, {
					"_off": 935, "_sz": 1, "opcode": { "_off": 935, "_sz": 1, "value": 142 }
				}, {
					"_off": 936, "_sz": 5, "opcode": { "_off": 936, "_sz": 1, "value": 143 },
					"oprand": { "_off": 937, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 941, "_sz": 1, "opcode": { "_off": 941, "_sz": 1, "value": 144 }
				}, {
					"_off": 942, "_sz": 1, "opcode": { "_off": 942, "_sz": 1, "value": 145 }
				}, {
					"_off": 943, "_sz": 1, "opcode": { "_off": 943, "_sz": 1, "value": 146 }
				}, {
					"_off": 944, "_sz": 1, "opcode": { "_off": 944, "_sz": 1, "value": 147 }
				}, {
					"_off": 945, "_sz": 1, "opcode": { "_off": 945, "_sz": 1, "value": 148 }
				}, {
					"_off": 946, "_sz": 1, "opcode": { "_off": 946, "_sz": 1, "value": 149 }
				}, {
					"_off": 947, "_sz": 1, "opcode": { "_off": 947, "_sz": 1, "value": 150 }
				}, {
					"_off": 948, "_sz": 1, "opcode": { "_off": 948, "_sz": 1, "value": 151 }
				}, {
					"_off": 949, "_sz": 1, "opcode": { "_off": 949, "_sz": 1, "value": 152 }
				}, {
					"_off": 950, "_sz": 1, "opcode": { "_off": 950, "_sz": 1, "value": 153 }
				}, {
					"_off": 951, "_sz": 1, "opcode": { "_off": 951, "_sz": 1, "value": 154 }
				}, {
					"_off": 952, "_sz": 1, "opcode": { "_off": 952, "_sz": 1, "value": 155 }
				}, {
					"_off": 953, "_sz": 1, "opcode": { "_off": 953, "_sz": 1, "value": 156 }
				}, {
					"_off": 954, "_sz": 1, "opcode": { "_off": 954, "_sz": 1, "value": 157 }
				}, {
					"_off": 955, "_sz": 1, "opcode": { "_off": 955, "_sz": 1, "value": 158 }
				}, {
					"_off": 956, "_sz": 1, "opcode": { "_off": 956, "_sz": 1, "value": 159 }
				}, {
					"_off": 957, "_sz": 1, "opcode": { "_off": 957, "_sz": 1, "value": 160 }
				}, {
					"_off": 958, "_sz": 1, "opcode": { "_off": 958, "_sz": 1, "value": 161 }
				}, {
					"_off": 959, "_sz": 1, "opcode": { "_off": 959, "_sz": 1, "value": 162 }
				}, {
					"_off": 960, "_sz": 5, "opcode": { "_off": 960, "_sz": 1, "value": 163 },
					"oprand": { "_off": 961, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 965, "_sz": 5, "opcode": { "_off": 965, "_sz": 1, "value": 164 },
					"oprand": { "_off": 966, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 970, "_sz": 5, "opcode": { "_off": 970, "_sz": 1, "value": 165 },
					"oprand": { "_off": 971, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 975, "_sz": 1, "opcode": { "_off": 975, "_sz": 1, "value": 179 }
				}, {
					"_off": 976, "_sz": 1, "opcode": { "_off": 976, "_sz": 1, "value": 180 }
				}, {
					"_off": 977, "_sz": 1, "opcode": { "_off": 977, "_sz": 1, "value": 181 }
				}, {
					"_off": 978, "_sz": 1, "opcode": { "_off": 978, "_sz": 1, "value": 182 }
				}, {
					"_off": 979, "_sz": 1, "opcode": { "_off": 979, "_sz": 1, "value": 183 }
				}, {
					"_off": 980, "_sz": 1, "opcode": { "_off": 980, "_sz": 1, "value": 184 }
				}, {
					"_off": 981, "_sz": 1, "opcode": { "_off": 981, "_sz": 1, "value": 185 }
				}, {
					"_off": 982, "_sz": 1, "opcode": { "_off": 982, "_sz": 1, "value": 186 }
				}, {
					"_off": 983, "_sz": 5, "opcode": { "_off": 983, "_sz": 1, "value": 194 },
					"oprand": { "_off": 984, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 988, "_sz": 1, "opcode": { "_off": 988, "_sz": 1, "value": 195 }
				}, {
					"_off": 989, "_sz": 5, "opcode": { "_off": 989, "_sz": 1, "value": 198 },
					"oprand": { "_off": 990, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 994, "_sz": 5, "opcode": { "_off": 994, "_sz": 1, "value": 208 },
					"oprand": { "_off": 995, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 999, "_sz": 1, "opcode": { "_off": 999, "_sz": 1, "value": 209 }
				}, {
					"_off": 1000, "_sz": 1, "opcode": { "_off": 1000, "_sz": 1, "value": 210 }
				}, {
					"_off": 1001, "_sz": 1, "opcode": { "_off": 1001, "_sz": 1, "value": 211 }
				}, {
					"_off": 1002, "_sz": 1, "opcode": { "_off": 1002, "_sz": 1, "value": 212 }
				}, {
					"_off": 1003, "_sz": 1, "opcode": { "_off": 1003, "_sz": 1, "value": 213 }
				}, {
					"_off": 1004, "_sz": 1, "opcode": { "_off": 1004, "_sz": 1, "value": 214 }
				}, {
					"_off": 1005, "_sz": 1, "opcode": { "_off": 1005, "_sz": 1, "value": 215 }
				}, {
					"_off": 1006, "_sz": 1, "opcode": { "_off": 1006, "_sz": 1, "value": 216 }
				}, {
					"_off": 1007, "_sz": 1, "opcode": { "_off": 1007, "_sz": 1, "value": 217 }
				}, {
					"_off": 1008, "_sz": 1, "opcode": { "_off": 1008, "_sz": 1, "value": 218 }
				}, {
					"_off": 1009, "_sz": 1, "opcode": { "_off": 1009, "_sz": 1, "value": 219 }
				}, {
					"_off": 1010, "_sz": 1, "opcode": { "_off": 1010, "_sz": 1, "value": 220 }
				}, {
					"_off": 1011, "_sz": 5, "opcode": { "_off": 1011, "_sz": 1, "value": 221 },
					"oprand": { "_off": 1012, "_sz": 4, "value": -412 }
				}, {
					"_off": 1016, "_sz": 2, "opcode": { "_off": 1016, "_sz": 1, "value": 222 },
					"oprand": { "_off": 1017, "_sz": 1, "value": 89 }
				}, {
					"_off": 1018, "_sz": 1, "opcode": { "_off": 1018, "_sz": 1, "value": 223 }
				}, {
					"_off": 1019, "_sz": 1, "opcode": { "_off": 1019, "_sz": 1, "value": 224 }
				}, {
					"_off": 1020, "_sz": 2, "opcode": { "_off": 1020, "_sz": 2, "value": 254 }
				}, {
					"_off": 1022, "_sz": 2, "opcode": { "_off": 1022, "_sz": 2, "value": 510 }
				}, {
					"_off": 1024, "_sz": 2, "opcode": { "_off": 1024, "_sz": 2, "value": 766 }
				}, {
					"_off": 1026, "_sz": 2, "opcode": { "_off": 1026, "_sz": 2, "value": 1022 }
				}, {
					"_off": 1028, "_sz": 2, "opcode": { "_off": 1028, "_sz": 2, "value": 1278 }
				}, {
					"_off": 1030, "_sz": 2, "opcode": { "_off": 1030, "_sz": 2, "value": 1534 }
				}, {
					"_off": 1032, "_sz": 6, "opcode": { "_off": 1032, "_sz": 2, "value": 1790 },
					"oprand": { "_off": 1034, "_sz": 4, "tid": 10, "rid": 2 }
				}, {
					"_off": 1038, "_sz": 6, "opcode": { "_off": 1038, "_sz": 2, "value": 2046 },
					"oprand": { "_off": 1040, "_sz": 4, "tid": 10, "rid": 2 }
				}, {
					"_off": 1044, "_sz": 6, "opcode": { "_off": 1044, "_sz": 2, "value": 2558 },
					"oprand": { "_off": 1046, "_sz": 4, "value": 184420862 }
				}, {
					"_off": 1050, "_sz": 6, "opcode": { "_off": 1050, "_sz": 2, "value": 2814 },
					"oprand": { "_off": 1052, "_sz": 4, "value": 201198590 }
				}, {
					"_off": 1056, "_sz": 6, "opcode": { "_off": 1056, "_sz": 2, "value": 3326 },
					"oprand": { "_off": 1058, "_sz": 4, "value": 234753278 }
				}, {
					"_off": 1062, "_sz": 6, "opcode": { "_off": 1062, "_sz": 2, "value": 3582 },
					"oprand": { "_off": 1064, "_sz": 4, "value": 251531006 }
				}, {
					"_off": 1068, "_sz": 2, "opcode": { "_off": 1068, "_sz": 2, "value": 4094 }
				}, {
					"_off": 1070, "_sz": 2, "opcode": { "_off": 1070, "_sz": 2, "value": 4606 }
				}, {
					"_off": 1072, "_sz": 3, "opcode": { "_off": 1072, "_sz": 2, "value": 4862 },
					"oprand": { "_off": 1074, "_sz": 1, "value": 1 }
				}, {
					"_off": 1075, "_sz": 2, "opcode": { "_off": 1075, "_sz": 2, "value": 5118 }
				}, {
					"_off": 1077, "_sz": 2, "opcode": { "_off": 1077, "_sz": 2, "value": 5374 }
				}, {
					"_off": 1079, "_sz": 6, "opcode": { "_off": 1079, "_sz": 2, "value": 5630 },
					"oprand": { "_off": 1081, "_sz": 4, "tid": 1, "rid": 3 }
				}, {
					"_off": 1085, "_sz": 6, "opcode": { "_off": 1085, "_sz": 2, "value": 5886 },
					"oprand": { "_off": 1087, "_sz": 4, "tid": 27, "rid": 2 }
				}, {
					"_off": 1091, "_sz": 2, "opcode": { "_off": 1091, "_sz": 2, "value": 6142 }
				}, {
					"_off": 1093, "_sz": 2, "opcode": { "_off": 1093, "_sz": 2, "value": 6398 }
				}, {
					"_off": 1095, "_sz": 2, "opcode": { "_off": 1095, "_sz": 2, "value": 6910 }
				}, {
					"_off": 1097, "_sz": 6, "opcode": { "_off": 1097, "_sz": 2, "value": 7422 },
					"oprand": { "_off": 1099, "_sz": 4, "tid": 27, "rid": 1 }
				}, {
					"_off": 1103, "_sz": 2, "opcode": { "_off": 1103, "_sz": 2, "value": 7678 }
				}, {
					"_off": 1105, "_sz": 2, "opcode": { "_off": 1105, "_sz": 2, "value": 7934 }
				}]
			});
		});

		test("ILEHSection.Simple", () => {
			const mr = peEH.mdtMethodDef.values[1];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 648, "_sz": 16, "values": [{
					"_off": 648, "_sz": 16,
					"Kind": { "_off": 648, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 649, "_sz": 1 },
					"Padding": { "_off": 650, "_sz": 2 },
					"Clauses": {
						"_off": 652, "_sz": 12, "values": [{
							"_off": 652, "_sz": 12,
							"Flags": { "_off": 652, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 654, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 656, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 657, "_sz": 2, "value": 15 },
							"HandlerLength": { "_off": 659, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 660, "_sz": 4, "value": 0x01000003 },
							"usage": 1
						}]
					},
					"dataSize": 16
				}]
			});
		});

		test("ILEHSection.SimpleFull", () => {
			const mr = peEH.mdtMethodDef.values[2];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 708, "_sz": 52, "values": [{
					"_off": 708, "_sz": 52,
					"Kind": { "_off": 708, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 709, "_sz": 1 },
					"Padding": { "_off": 710, "_sz": 2 },
					"Clauses": {
						"_off": 712, "_sz": 48, "values": [{
							"_off": 712, "_sz": 12,
							"Flags": { "_off": 712, "_sz": 2, "value": 1 },
							"TryOffset": { "_off": 714, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 716, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 717, "_sz": 2, "value": 18 },
							"HandlerLength": { "_off": 719, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 720, "_sz": 4, "value": 15 },
							"usage": 2
						}, {
							"_off": 724, "_sz": 12,
							"Flags": { "_off": 724, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 726, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 728, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 729, "_sz": 2, "value": 23 },
							"HandlerLength": { "_off": 731, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 732, "_sz": 4, "value": 0x01000003 },
							"usage": 1
						}, {
							"_off": 736, "_sz": 12,
							"Flags": { "_off": 736, "_sz": 2, "value": 4 },
							"TryOffset": { "_off": 738, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 740, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 741, "_sz": 2, "value": 28 },
							"HandlerLength": { "_off": 743, "_sz": 1, "value": 1 },
							"ClassTokenOrFilterOffset": { "_off": 744, "_sz": 4, "value": 0x01000003 },
							"usage": 1
						}, {
							"_off": 748, "_sz": 12,
							"Flags": { "_off": 748, "_sz": 2, "value": 2 },
							"TryOffset": { "_off": 750, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 752, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 753, "_sz": 2, "value": 29 },
							"HandlerLength": { "_off": 755, "_sz": 1, "value": 1 },
							"ClassTokenOrFilterOffset": { "_off": 756, "_sz": 4, "value": 0x01000003 },
							"usage": 1
						}]
					},
					"dataSize": 52
				}]
			});
		});

		test("ILEHSection.ComplicatedFull", () => {
			const mr = peEH.mdtMethodDef.values[3];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 916, "_sz": 100, "values": [{
					"_off": 916, "_sz": 100,
					"Kind": { "_off": 916, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 917, "_sz": 1 },
					"Padding": { "_off": 918, "_sz": 2 },
					"Clauses": {
						"_off": 920, "_sz": 96, "values": [{
							"_off": 920, "_sz": 12,
							"Flags": { "_off": 920, "_sz": 2, "value": 1 },
							"TryOffset": { "_off": 922, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 924, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 925, "_sz": 2, "value": 28 },
							"HandlerLength": { "_off": 927, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 928, "_sz": 4, "value": 15 },
							"usage": 2
						}, {
							"_off": 932, "_sz": 12,
							"Flags": { "_off": 932, "_sz": 2, "value": 2 },
							"TryOffset": { "_off": 934, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 936, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 937, "_sz": 2, "value": 43 },
							"HandlerLength": { "_off": 939, "_sz": 1, "value": 11 },
							"ClassTokenOrFilterOffset": { "_off": 940, "_sz": 4, "value": 15 },
							"usage": 2
						}, {
							"_off": 944, "_sz": 12,
							"Flags": { "_off": 944, "_sz": 2, "value": 1 },
							"TryOffset": { "_off": 946, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 948, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 949, "_sz": 2, "value": 67 },
							"HandlerLength": { "_off": 951, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 952, "_sz": 4, "value": 54 },
							"usage": 2
						}, {
							"_off": 956, "_sz": 12,
							"Flags": { "_off": 956, "_sz": 2, "value": 4 },
							"TryOffset": { "_off": 958, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 960, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 961, "_sz": 2, "value": 82 },
							"HandlerLength": { "_off": 963, "_sz": 1, "value": 11 },
							"ClassTokenOrFilterOffset": { "_off": 964, "_sz": 4, "value": 54 },
							"usage": 2
						}, {
							"_off": 968, "_sz": 12,
							"Flags": { "_off": 968, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 970, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 972, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 973, "_sz": 2, "value": 93 },
							"HandlerLength": { "_off": 975, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 976, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 980, "_sz": 12,
							"Flags": { "_off": 980, "_sz": 2, "value": 2 },
							"TryOffset": { "_off": 982, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 984, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 985, "_sz": 2, "value": 108 },
							"HandlerLength": { "_off": 987, "_sz": 1, "value": 11 },
							"ClassTokenOrFilterOffset": { "_off": 988, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 992, "_sz": 12,
							"Flags": { "_off": 992, "_sz": 2, "value": 2 },
							"TryOffset": { "_off": 994, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 996, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 997, "_sz": 2, "value": 119 },
							"HandlerLength": { "_off": 999, "_sz": 1, "value": 11 },
							"ClassTokenOrFilterOffset": { "_off": 1000, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1004, "_sz": 12,
							"Flags": { "_off": 1004, "_sz": 2, "value": 4 },
							"TryOffset": { "_off": 1006, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1008, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 1009, "_sz": 2, "value": 130 },
							"HandlerLength": { "_off": 1011, "_sz": 1, "value": 11 },
							"ClassTokenOrFilterOffset": { "_off": 1012, "_sz": 4, "value": 16777219 },
							"usage": 1
						}]
					},
					"dataSize": 100
				}]
			});
		});

		test("ILEHSection.Embedded2Level", () => {
			const mr = peEH.mdtMethodDef.values[4];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 1096, "_sz": 28, "values": [{
					"_off": 1096, "_sz": 28,
					"Kind": { "_off": 1096, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 1097, "_sz": 1 },
					"Padding": { "_off": 1098, "_sz": 2 },
					"Clauses": {
						"_off": 1100, "_sz": 24, "values": [{
							"_off": 1100, "_sz": 12,
							"Flags": { "_off": 1100, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1102, "_sz": 2, "value": 10 },
							"TryLength": { "_off": 1104, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 1105, "_sz": 2, "value": 25 },
							"HandlerLength": { "_off": 1107, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1108, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1112, "_sz": 12,
							"Flags": { "_off": 1112, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1114, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1116, "_sz": 1, "value": 50 },
							"HandlerOffset": { "_off": 1117, "_sz": 2, "value": 50 },
							"HandlerLength": { "_off": 1119, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1120, "_sz": 4, "value": 16777219 },
							"usage": 1
						}]
					},
					"dataSize": 28
				}]
			});
		});

		test("ILEHSection.Embedded2LevelContinuous", () => {
			const mr = peEH.mdtMethodDef.values[5];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 1256, "_sz": 64, "values": [{
					"_off": 1256, "_sz": 64,
					"Kind": { "_off": 1256, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 1257, "_sz": 1 },
					"Padding": { "_off": 1258, "_sz": 2 },
					"Clauses": {
						"_off": 1260, "_sz": 60, "values": [{
							"_off": 1260, "_sz": 12,
							"Flags": { "_off": 1260, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1262, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1264, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 1265, "_sz": 2, "value": 15 },
							"HandlerLength": { "_off": 1267, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1268, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1272, "_sz": 12,
							"Flags": { "_off": 1272, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1274, "_sz": 2, "value": 30 },
							"TryLength": { "_off": 1276, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 1277, "_sz": 2, "value": 45 },
							"HandlerLength": { "_off": 1279, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1280, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1284, "_sz": 12,
							"Flags": { "_off": 1284, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1286, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1288, "_sz": 1, "value": 60 },
							"HandlerOffset": { "_off": 1289, "_sz": 2, "value": 60 },
							"HandlerLength": { "_off": 1291, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1292, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1296, "_sz": 12,
							"Flags": { "_off": 1296, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1298, "_sz": 2, "value": 75 },
							"TryLength": { "_off": 1300, "_sz": 1, "value": 15 },
							"HandlerOffset": { "_off": 1301, "_sz": 2, "value": 90 },
							"HandlerLength": { "_off": 1303, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1304, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1308, "_sz": 12,
							"Flags": { "_off": 1308, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1310, "_sz": 2, "value": 75 },
							"TryLength": { "_off": 1312, "_sz": 1, "value": 30 },
							"HandlerOffset": { "_off": 1313, "_sz": 2, "value": 105 },
							"HandlerLength": { "_off": 1315, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1316, "_sz": 4, "value": 16777219 },
							"usage": 1
						}]
					},
					"dataSize": 64
				}]
			});
		});

		test("ILEHSection.Embedded3Level", () => {
			const mr = peEH.mdtMethodDef.values[6];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 1416, "_sz": 100, "values": [{
					"_off": 1416, "_sz": 100,
					"Kind": { "_off": 1416, "_sz": 1, "value": 1 },
					"DataSizeBytes": { "_off": 1417, "_sz": 1 },
					"Padding": { "_off": 1418, "_sz": 2 },
					"Clauses": {
						"_off": 1420, "_sz": 96, "values": [{
							"_off": 1420, "_sz": 12,
							"Flags": { "_off": 1420, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1422, "_sz": 2, "value": 5 },
							"TryLength": { "_off": 1424, "_sz": 1, "value": 10 },
							"HandlerOffset": { "_off": 1425, "_sz": 2, "value": 15 },
							"HandlerLength": { "_off": 1427, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1428, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1432, "_sz": 12,
							"Flags": { "_off": 1432, "_sz": 2, "value": 1 },
							"TryOffset": { "_off": 1434, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1436, "_sz": 1, "value": 5 },
							"HandlerOffset": { "_off": 1437, "_sz": 2, "value": 22 },
							"HandlerLength": { "_off": 1439, "_sz": 1, "value": 15 },
							"ClassTokenOrFilterOffset": { "_off": 1440, "_sz": 4, "value": 5 },
							"usage": 2
						}, {
							"_off": 1444, "_sz": 12,
							"Flags": { "_off": 1444, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1446, "_sz": 2, "value": 0 },
							"TryLength": { "_off": 1448, "_sz": 1, "value": 5 },
							"HandlerOffset": { "_off": 1449, "_sz": 2, "value": 37 },
							"HandlerLength": { "_off": 1451, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1452, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1456, "_sz": 12,
							"Flags": { "_off": 1456, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1458, "_sz": 2, "value": 42 },
							"TryLength": { "_off": 1460, "_sz": 1, "value": 5 },
							"HandlerOffset": { "_off": 1461, "_sz": 2, "value": 47 },
							"HandlerLength": { "_off": 1463, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1464, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1468, "_sz": 12,
							"Flags": { "_off": 1468, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1470, "_sz": 2, "value": 52 },
							"TryLength": { "_off": 1472, "_sz": 1, "value": 5 },
							"HandlerOffset": { "_off": 1473, "_sz": 2, "value": 57 },
							"HandlerLength": { "_off": 1475, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1476, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1480, "_sz": 12,
							"Flags": { "_off": 1480, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1482, "_sz": 2, "value": 42 },
							"TryLength": { "_off": 1484, "_sz": 1, "value": 20 },
							"HandlerOffset": { "_off": 1485, "_sz": 2, "value": 62 },
							"HandlerLength": { "_off": 1487, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1488, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1492, "_sz": 12,
							"Flags": { "_off": 1492, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1494, "_sz": 2, "value": 67 },
							"TryLength": { "_off": 1496, "_sz": 1, "value": 5 },
							"HandlerOffset": { "_off": 1497, "_sz": 2, "value": 72 },
							"HandlerLength": { "_off": 1499, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1500, "_sz": 4, "value": 16777219 },
							"usage": 1
						}, {
							"_off": 1504, "_sz": 12,
							"Flags": { "_off": 1504, "_sz": 2, "value": 0 },
							"TryOffset": { "_off": 1506, "_sz": 2, "value": 42 },
							"TryLength": { "_off": 1508, "_sz": 1, "value": 35 },
							"HandlerOffset": { "_off": 1509, "_sz": 2, "value": 77 },
							"HandlerLength": { "_off": 1511, "_sz": 1, "value": 5 },
							"ClassTokenOrFilterOffset": { "_off": 1512, "_sz": 4, "value": 16777219 },
							"usage": 1
						}]
					},
					"dataSize": 100
				}]
			});
		});

		test("ILEHSection.FatSection", () => {
			const mr = peEH.mdtMethodDef.values[7];
			const m = PE.loadIL(peEH, mr);
			expect(m.Sections).toEqual({
				"_off": 1804, "_sz": 28, "values": [{
					"_off": 1804, "_sz": 28,
					"Kind": { "_off": 1804, "_sz": 1, "value": 65 },
					"DataSizeBytes": { "_off": 1805, "_sz": 3 },
					"Clauses": {
						"_off": 1808, "_sz": 24, "values": [{
							"_off": 1808, "_sz": 24,
							"Flags": { "_off": 1808, "_sz": 4, "value": 0 },
							"TryOffset": { "_off": 1812, "_sz": 4, "value": 0 },
							"TryLength": { "_off": 1816, "_sz": 4, "value": 265 },
							"HandlerOffset": { "_off": 1820, "_sz": 4, "value": 265 },
							"HandlerLength": { "_off": 1824, "_sz": 4, "value": 10 },
							"ClassTokenOrFilterOffset": { "_off": 1828, "_sz": 4, "value": 16777219 },
							"usage": 1
						}]
					},
					"dataSize": 28
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
