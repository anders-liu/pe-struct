export enum PeErrorType {
	Unknown,
	FileTooShort,
	FileTooLong,
	InvalidOffset,
	InvalidSize,
	InvalidFilePointer,
	InvalidDosSignature,
	InvalidPeSignature,
	InvalidSizeOfOptionalHeader,
	InvalidOptionalHeaderMagic,
	InvalidNumberOfDataDirectories,
	InvalidSizeOfCliHeader,
	InvalidMdSignature,
	InvalidMethodHeaderFormat,
	InvalidILOpcode,
}

export class PeError {
	public constructor(
		readonly type: PeErrorType,
		readonly offset: number,
		readonly size: number,
		readonly value?: number) { }
}
