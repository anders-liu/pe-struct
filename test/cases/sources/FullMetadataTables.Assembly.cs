[assembly: System.Reflection.AssemblyVersion("1.2.3.4")]

#pragma warning disable CS0414  // The field '...' is assigned but its value is never used

namespace AndersLiu.PeFormat.TestCases.FullMetadataTables
{
	using System;
	using System.Collections.Generic;
	using System.Globalization;
	using System.Reflection;
	using System.Resources;
	using System.Runtime.InteropServices;
	using System.Security.Permissions;
	using System.Threading;

	public class Program
	{
		public static string StaticField = "hello";
		public static readonly int StaticReadonlyField = -10;

		private double InstanceField = 1.0;
		private readonly decimal InstanceReadonlyField = 10.01m;

		const int IntConst = 1;
		const string StringConst = "StringConst";

		private Dictionary<int, List<int[]>> ComplicatedField = null;

		public event EventHandler CustomEvent1;

		private void ReaseCustomEvent1()
		{
			var handler = this.CustomEvent1;
			if(handler != null)
				handler(this, new EventArgs());
		}

		public event EventHandler<CustomEventArgs> CustomEvent2;

		private void ReaseCustomEvent2()
		{
			var handler = this.CustomEvent2;
			if(handler != null)
				handler(this, new CustomEventArgs(999));
		}

		public int PublicIntProperty
		{
			get; private set;
		}

		public string PublicStringProperty
		{
			get; private set;
		}

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool MessageBeep(uint uType);

		public static void Main(string[] args)
		{
			Console.WriteLine("Hello");

			// Access resources.
			var newCulture = new CultureInfo(args[0]);
			Thread.CurrentThread.CurrentCulture = newCulture;
			Thread.CurrentThread.CurrentUICulture = newCulture;
			Assembly assembly = typeof(Program).Assembly;
			var resman = new ResourceManager("FullMetadataTables.Resources", assembly);
			var greeting = resman.GetString("HelloString");
			Console.WriteLine(greeting);

			// Access netmodule.
			var greetingFromModule = ModuleType.GetHelloString("Anders Liu");
			Console.WriteLine(greetingFromModule);
		}

		public int MethodWith2Params(int a1, string b1)
		{
			throw new NotImplementedException("MethodWith2Params");
		}

		public List<Dictionary<string, int[]>> MethodWith1Param(int a2)
		{
			throw new NotImplementedException("MethodWith1Param");
		}

		public void MethodWithDefaultParam(int intParam = 10, string stringParam = "hello")
		{
		}

		[FileIOPermission(SecurityAction.Demand)]
		private void MethodDemandsFileIOPermission()
		{
		}

		private TOutput GenericMethod<TOutput, TInput>(TInput input)
			where TOutput : Program
			where TInput : new()
		{
			return default(TOutput);
		}

		private void CallGenericMethod()
		{
			var output = GenericMethod<Program, Program>(new Program());
		}

		private class NestedClassA
		{
		}

		public class PublicNestedClass
		{
		}
	}

	public interface ISimpleInterface1
	{
		void Method1();
	}

	public interface ISimpleInterface2
	{
		void Method2();
	}

	public class ClassImplementsSimpleInterfaces
		: ISimpleInterface1, ISimpleInterface2, IDisposable
	{
		public void Method1() {}

		void ISimpleInterface2.Method2() {}

		public void Dispose() {}
	}

	public struct HasMarshal
	{
		[MarshalAs(UnmanagedType.I4)]
		public int IntField;

		[MarshalAs(UnmanagedType.LPTStr)]
		public string StringField;

		[MarshalAs(UnmanagedType.ByValArray)]
		public int[] IntArrayField;

		[return:MarshalAs(UnmanagedType.I4)]
		public int InteropMethod([MarshalAs(UnmanagedType.LPTStr)]string name)
		{
			return 0;
		}
	}

	[StructLayout(LayoutKind.Explicit, Pack = 8, Size = 8)]
	public struct ExplicitLayoutStruct
	{
		[FieldOffset(0)] public uint DwordValue;

		[FieldOffset(0)] public ushort Word1;
		[FieldOffset(2)] public ushort Word2;

		[FieldOffset(0)] public byte Byte1;
		[FieldOffset(1)] public byte Byte2;
		[FieldOffset(2)] public byte Byte3;
		[FieldOffset(3)] public byte Byte4;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 8, Size = 8)]
	public struct SequentialLayoutStruct
	{
		public byte Byte1;
		public byte Byte2;
		public byte Byte3;
		public byte Byte4;
	}

	public class CustomEventArgs : EventArgs
	{
		public CustomEventArgs(int data)
		{
			this.Data = data;
		}

		public int Data { get; private set; }
	}

	public class GenericClass<TProgram, TOther>
		where TProgram : Program, new()
		where TOther : new()
	{
	}
}
