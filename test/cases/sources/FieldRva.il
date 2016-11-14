.assembly extern mscorlib { auto }
.assembly FieldRva { }
.module FieldRva.exe

.data MagicNumberData = int32(123456)

.namespace AndersLiu.PeFormat.TestCases.FieldRva
{
	.class public auto ansi Program extends [mscorlib]System.Object
	{
		.field public static int32 MagicNumber at MagicNumberData

		.method public static void Main() cil managed
		{
			.entrypoint
			ldsfld int32 AndersLiu.PeFormat.TestCases.FieldRva.Program::MagicNumber
			call void [mscorlib]System.Console::WriteLine(int32)
		}
	}
}
