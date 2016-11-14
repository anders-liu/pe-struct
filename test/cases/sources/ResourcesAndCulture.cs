namespace AndersLiu.PeFormat.TestCases.ResourcesAndCulture
{
    using System;
    using System.Globalization;
    using System.Resources;
    using System.Threading;


    class Program
    {
        static void Main(string[] args)
        {
            var rm = new ResourceManager("ResourcesAndCulture.Resources", typeof(Program).Assembly);
                var newCulture = new CultureInfo(args[0]);
                Thread.CurrentThread.CurrentCulture = newCulture;
                Thread.CurrentThread.CurrentUICulture = newCulture;
                string greeting = String.Format("The current culture is {0}.\n{1}",
                                                Thread.CurrentThread.CurrentUICulture.Name,
                                                rm.GetString("HelloString"));
                Console.WriteLine(greeting);
        }
    }
}
