/// <reference path="../typings/index.d.ts" />
/// <reference path="../def/pe-struct.d.ts" />

import * as PE from "pe-struct";
import * as FS from "fs";

export class TestCases {
	static load(name: string): PE.PeStruct {
		if (!TestCases.cache[name]) {
			const buf = FS.readFileSync("./test/cases/targets/" + name);
			const ab = new Uint8Array(buf).buffer;
			TestCases.cache[name] = PE.load(ab);
		}
		return TestCases.cache[name];
	}

	private static readonly cache: { [name: string]: PE.PeStruct } = {};
}

export function expectPeError(type: PE.PeErrorType, func: () => void) {
	try {
		func();
		fail("No expected error thrown.");
	} catch (err) {
		let peErr = err as PE.PeError;
		if (!err)
			fail("Not a PE error.");

		if (peErr.type != type)
			fail(`(${PE.PeErrorType[peErr.type]}) is not a wanted error (${PE.PeErrorType[type]}).`);
	}
}

export function expectError(func: () => void) {
	try {
		func();
		fail("No expected error thrown.");
	} catch (e) {
	}
}