namespace AndersLiu.PeFormat.TestCases.FullMetadataTables
{
    using System;

    public class ModuleType
    {
        public static string GetHelloString(string name)
        {
            if(name == null)
                throw new ArgumentNullException("name");

            return GetHelloStringInternal(name);
        }

        internal static string GetHelloStringInternal(string name)
        {
            return string.Format("Hello, {0}!", name);
        }
    }
}
