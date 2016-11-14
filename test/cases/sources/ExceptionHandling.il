.assembly extern mscorlib { auto }
.assembly ExceptionHandling { }
.module ExceptionHandling.exe

.namespace AndersLiu.PeFormat.TestCases.ExceptionHandling
{
	.class public auto ansi Program extends [mscorlib]System.Object
	{
		.method public static void Main() cil managed
		{
			.entrypoint
			ldstr "Main"
			call void [mscorlib]System.Console::WriteLine(string)
		}

		.method public static void Simple() cil managed
		{
			.try
			{
				ldstr "Simple:try"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			catch [mscorlib]System.Exception
			{
				ldstr "Simple:catch(Exception)"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
LEAVE1:
		}

		.method private static void SimpleFull() cil managed
		{
			.try
			{
				ldstr "SimpleFull:try"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			filter
			{
				ldc.i4.0
				endfilter
			}
			{
				leave LEAVE1
			}
			catch [mscorlib]System.Exception
			{
				leave LEAVE1
			}
			fault
			{
				endfault
			}
			finally
			{
				endfinally
			}
LEAVE1:
		}

		.method private static void ComplicatedFull() cil managed
		{
			.try
			{
				ldstr "ComplicatedFull:try"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			filter
			{
				ldstr "ComplicatedFull:filter1"
				call void [mscorlib]System.Console::WriteLine(string)
				ldc.i4.1
				endfilter
			}
			{
				ldstr "ComplicatedFull:filter1-handler"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			finally
			{
				ldstr "ComplicatedFull:filter1-finally"
				call void [mscorlib]System.Console::WriteLine(string)
				endfinally
			}
			filter
			{
				ldstr "ComplicatedFull:filter2"
				call void [mscorlib]System.Console::WriteLine(string)
				ldc.i4.1
				endfilter
			}
			{
				ldstr "ComplicatedFull:filter2-handler"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			fault
			{
				ldstr "ComplicatedFull:filter2-fault"
				call void [mscorlib]System.Console::WriteLine(string)
				endfault
			}
			catch [mscorlib]System.Exception
			{
				ldstr "ComplicatedFull:catch(Exception)"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			finally
			{
				ldstr "ComplicatedFull:catch(Exception)-finally"
				call void [mscorlib]System.Console::WriteLine(string)
				endfinally
			}
			finally
			{
				ldstr "ComplicatedFull:catch(Exception)-finally2"
				call void [mscorlib]System.Console::WriteLine(string)
				endfinally
			}
			fault
			{
				ldstr "ComplicatedFull:catch(Exception)-fault"
				call void [mscorlib]System.Console::WriteLine(string)
				endfault
			}
LEAVE1:
		}

		.method private static void Embedded2Level() cil managed
		{
			.try
			{
				ldstr "Embedded2Level>L1:try"
				call void [mscorlib]System.Console::WriteLine(string)
				.try
				{
					ldstr "Embedded2Level>L2:try"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				catch [mscorlib]System.Exception
				{
					ldstr "Embedded2Level>L2:catch(Exception)"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				ldstr "Embedded2Level>L1:after-L2-try-catch"
				call void [mscorlib]System.Console::WriteLine(string)
LEAVE2:
			}
			catch [mscorlib]System.Exception
			{
				ldstr "Embedded2Level>L1:catch(Exception)"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
LEAVE1:
		}

		.method private static void Embedded2LevelContinuous() cil managed
		{
			.try
			{
				.try
				{
					ldstr "Embedded2LevelContinuous>L2:try"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				catch [mscorlib]System.Exception
				{
					ldstr "Embedded2LevelContinuous>L2:catch(Exception)"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				.try
				{
					ldstr "Embedded2LevelContinuous>L2:try2"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				catch [mscorlib]System.Exception
				{
					ldstr "Embedded2LevelContinuous>L2:catch2(Exception)"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
LEAVE2:
			}
			catch [mscorlib]System.Exception
			{
				ldstr "Embedded2LevelContinuous>L1:catch(Exception)"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
LEAVE1:
			.try
			{
				.try
				{
					ldstr "Embedded2LevelContinuous>L2:try"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
				catch [mscorlib]System.Exception
				{
					ldstr "Embedded2LevelContinuous>L2:catch(Exception)"
					call void [mscorlib]System.Console::WriteLine(string)
					leave LEAVE2
				}
			}
			catch [mscorlib]System.Exception
			{
				ldstr "Embedded2LevelContinuous>L1:catch(Exception)"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
		}

		.method private static void Embedded3Level() cil managed
		{
			.try
			{
				leave LEAVE1
			}
			filter
			{
				.try
				{
					ldstr "try-in-filter"
					call void [mscorlib]System.Console::WriteLine(string)
				}
				catch [mscorlib]System.Exception
				{
					leave LEAVE1
				}
				endfilter
			}
			{
				ldstr "filter-handler"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE1
			}
			catch [mscorlib]System.Exception
			{
				leave LEAVE1
			}
			.try
			{
				.try
				{
					.try
					{
						leave LEAVE1
					}
					catch [mscorlib]System.Exception
					{
						leave LEAVE1
					}
					.try
					{
						leave LEAVE1
					}
					catch [mscorlib]System.Exception
					{
						leave LEAVE1
					}
				}
				catch [mscorlib]System.Exception
				{
					leave LEAVE1
				}
				.try
				{
					leave LEAVE1
				}
				catch [mscorlib]System.Exception
				{
					leave LEAVE1
				}
			}
			catch [mscorlib]System.Exception
			{
				leave LEAVE1
			}
LEAVE1:
		}

		.method private static void FatSection() cil managed
		{
			.try
			{
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				ldstr "SimpleEH"
				call void [mscorlib]System.Console::WriteLine(string)
				leave LEAVE
			}
			catch [mscorlib]System.Exception
			{
				call instance string [mscorlib]System.Exception::ToString()
				leave LEAVE
			}
LEAVE:
		}
	}
}
