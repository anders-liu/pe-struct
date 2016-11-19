.assembly extern mscorlib { auto }
.assembly FullIL { }
.module FullIL.exe

.namespace AndersLiu.PeFormat.TestCases.FullIL
{
	.class public auto ansi Program<T> extends [mscorlib]System.Object
	{
		.method public static void Main() cil managed
		{
			.entrypoint
begin:
			nop
			break
			ldarg.0
			ldarg.1
			ldarg.2
			ldarg.3
			ldloc.0
			ldloc.1
			ldloc.2
			ldloc.3
			stloc.0
			stloc.1
			stloc.2
			stloc.3
			ldarg.s        14
			ldarga.s       15
			starg.s        16
			ldloc.s        17
			ldloca.s       18
			stloc.s        19
			ldnull
			ldc.i4.m1
			ldc.i4.0
			ldc.i4.1
			ldc.i4.2
			ldc.i4.3
			ldc.i4.4
			ldc.i4.5
			ldc.i4.6
			ldc.i4.7
			ldc.i4.8
			ldc.i4.s        -31
			ldc.i4          -32
			ldc.i8          -33
			ldc.r4           34.34
			ldc.r8           35.35
			dup
			pop
			jmp              void [mscorlib]System.Console::WriteLine(string)
			call             void [mscorlib]System.Console::WriteLine(string)
			calli            void (string)
middle:
			ret
			br.s             middle
			brfalse.s        middle
			brtrue.s         middle
			beq.s            middle
			bge.s            middle
			bgt.s            middle
			ble.s            middle
			blt.s            middle
			bne.un.s         middle
			bge.un.s         middle
			bgt.un.s         middle
			ble.un.s         middle
			blt.un.s         middle
			br               begin
			brfalse          begin
			brtrue           begin
			beq              begin
			bge              begin
			bgt              begin
			ble              begin
			blt              begin
			bne.un           begin
			bge.un           begin
			bgt.un           begin
			ble.un           begin
			blt.un           begin
			switch           (begin, middle, end);
			ldind.i1
			ldind.u1
			ldind.i2
			ldind.u2
			ldind.i4
			ldind.u4
			ldind.i8
			ldind.i
			ldind.r4
			ldind.r8
			ldind.ref
			stind.ref
			stind.i1
			stind.i2
			stind.i4
			stind.i8
			stind.r4
			stind.r8
			add
			sub
			mul
			div
			div.un
			rem
			rem.un
			and
			or
			xor
			shl
			shr
			shr.un
			neg
			not
			conv.i1
			conv.i2
			conv.i4
			conv.i8
			conv.r4
			conv.r8
			conv.u4
			conv.u8
			callvirt          instance void [mscorlib]System.Console::WriteLine(string)
			cpobj             [mscorlib]System.String
			ldobj             [mscorlib]System.String
			ldstr             "ldstr 114"
			newobj            instance void [mscorlib]System.Object::.ctor()
			castclass         [mscorlib]System.String
			isinst            [mscorlib]System.String
			conv.r.un
			unbox             valuetype [mscorlib]System.Int32
			throw
			ldfld             int32 System.String::Length
			ldflda            int32 System.String::Length
			stfld             int32 System.String::Length
			ldsfld            int32 System.String::Length
			ldsflda           int32 System.String::Length
			stsfld            int32 System.String::Length
			stobj             [mscorlib]System.String
			conv.ovf.i1.un
			conv.ovf.i2.un
			conv.ovf.i4.un
			conv.ovf.i8.un
			conv.ovf.u1.un
			conv.ovf.u2.un
			conv.ovf.u4.un
			conv.ovf.u8.un
			conv.ovf.i.un
			conv.ovf.u.un
			box               valuetype [mscorlib]System.Int32
			newarr            [mscorlib]System.Object
			ldlen
			ldelema           [mscorlib]System.String
			ldelem.i1
			ldelem.u1
			ldelem.i2
			ldelem.u2
			ldelem.i4
			ldelem.u4
			ldelem.i8
			ldelem.i
			ldelem.r4
			ldelem.r8
			ldelem.ref
			stelem.i
			stelem.i1
			stelem.i2
			stelem.i4
			stelem.i8
			stelem.r4
			stelem.r8
			stelem.ref
			ldelem            [mscorlib]System.String
			stelem            [mscorlib]System.String
			unbox.any         valuetype [mscorlib]System.Int32
			conv.ovf.i1
			conv.ovf.u1
			conv.ovf.i2
			conv.ovf.u2
			conv.ovf.i4
			conv.ovf.u4
			conv.ovf.i8
			conv.ovf.u8
			refanyval         valuetype [mscorlib]System.Int32
			ckfinite
			mkrefany          valuetype [mscorlib]System.Int32
			ldtoken           valuetype [mscorlib]System.Int32
			conv.u2
			conv.u1
			conv.i
			conv.ovf.i
			conv.ovf.u
			add.ovf
			add.ovf.un
			mul.ovf
			mul.ovf.un
			sub.ovf
			sub.ovf.un
			endfinally
			leave             begin
			leave.s           end
			stind.i
			conv.u
			arglist
			ceq
			cgt
			cgt.un
			clt
			clt.un
			ldftn             instance void [mscorlib]System.Console::WriteLine(string)
			ldvirtftn         instance void [mscorlib]System.Console::WriteLine(string)
			ldarg             2558
			ldarga            2814
			starg             3070
			ldloc             3326
			ldloca            3582
			stloc             3838
			localloc
			endfilter
			unaligned.        1
			volatile.
			tail.
			initobj           [mscorlib]System.String
			constrained.      !T
			cpblk
			initblk
			//no.
			rethrow
			sizeof            valuetype [mscorlib]System.Int32
			refanytype
			readonly.
end:
		}
	}
}
