﻿using System;
using SharpWnfInject.Handler;

namespace SharpWnfInject
{
    internal class SharpWnfInject
    {
        static void Main(string[] args)
        {
            var options = new CommandLineParser();

            try
            {
                options.SetTitle("SharpWnfInject - Tool to investigate WNF code injection technique.");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddParameter(true, "n", "name", null, "Specifies WNF State Name to inject. Hex format or Well-known name format is accepted.");
                options.AddParameter(true, "p", "pid", null, "Specifies PID to inject.");
                options.AddParameter(true, "i", "input", null, "Specifies the file path to shellcode.");
                options.AddParameter(false, "r", "registry", null, "Specifies whether or not to modify security descriptor.");
                options.AddFlag(false, "d", "debug", "Flag to enable SeDebugPrivilege. Requires administrative privilege.");
                options.Parse(args);
                Execute.Run(options);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);

                return;
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);

                return;
            }
        }
    }
}
