using System;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Security.Principal;
using trout.util;

namespace trout
{
    public static class AppSettings
    {
        // Static property to store the verbose flag
        public static bool IsVerbose { get; set; } = false;
    }

    class Trout
    {
        

        public static void printHelp()
        {
            Console.WriteLine("Invalid command. Usage: detect | exploit | cleanup");
            Console.WriteLine("Options:");
            Console.WriteLine("  -v, --verbose    Enable verbose output for more detailed information.");
        }

        static void Main(string[] args)
        {
            string domain = string.Empty;
            string username = string.Empty;
            string password = string.Empty;

            // Parse arguments for domain (-d), username (-u), and password (-p)
            if (args.Length > 0)
            {
                // Check if user supplied domain, username, or password options
                domain = GetArgumentValue(args, "-d") ?? domain;
                username = GetArgumentValue(args, "-u") ?? string.Empty;
                password = GetArgumentValue(args, "-p") ?? string.Empty;
                AppSettings.IsVerbose = IsFlagPresent(args, "-v");
            }

            if (args.Length == 0 || args[0].ToLower() == "help")
            {
                printHelp();
                return;
            }

            string command = args[0].ToLower();

            switch (command)
            {
                case "detect":
                    HandleDetect(domain, username, password);
                    break;

                case "exploit":
                    HandleExploit(domain, username, password, args);
                    break;

                case "cleanup":
                    HandleCleanup(domain, username, password, args);
                    break;

                default:
                    printHelp();
                    break;
            }
        }

        // Get the current domain
        static string getFQDN()
        {
            // Get the current domain information
            Domain domain = Domain.GetComputerDomain();

            // Get the FQDN (domain name) of the domain
            return domain.Name;
        }

        // Get the value of a specific argument
        static string GetArgumentValue(string[] args, string argument)
        {
            int index = Array.IndexOf(args, argument);
            if (index >= 0 && index + 1 < args.Length)
            {
                return args[index + 1];
            }
            return null;
        }

        static bool IsFlagPresent(string[] args, string flag)
        {
                return Array.Exists(args, arg => arg.Equals(flag, StringComparison.OrdinalIgnoreCase));
        }
        

        // Handle detect command
        static void HandleDetect(string domain, string username, string password)
        {
            Console.WriteLine("Running detection...");

            NetworkCredential credentials;

            bool impersonate = false;

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                credentials = CredentialCache.DefaultNetworkCredentials; // Use current Windows user

                
            }
            else
            {
                credentials = new NetworkCredential(username, password, domain);
                impersonate = true;
            }

            credentials.Domain = string.IsNullOrEmpty(domain) ? getFQDN() : domain;

            if (impersonate)
            {
                using (WindowsImpersonationContext impersonationContext = Impersonation.ImpersonateUser(credentials))
                {
                    Detect.invoke(credentials);
                }

            }
            else
            {
                Detect.invoke(credentials);

            }
            
        }

        // Handle exploit command
        static void HandleExploit(string domain, string username, string password, string[] args)
        {
            Console.WriteLine("Running exploit...");

            // Additional options for exploit
            if (args.Length > 1)
            {
                string exploitOption = args[1].ToLower();
                switch (exploitOption)
                {
                    case "option1":
                        Console.WriteLine("Exploit option 1 selected.");
                        break;
                    case "option2":
                        Console.WriteLine("Exploit option 2 selected.");
                        break;
                    default:
                        Console.WriteLine("Invalid exploit option. Available options: option1, option2.");
                        break;
                }
            }
            else
            {
                Console.WriteLine("No exploit option provided. Usage: exploit option1 | option2");
            }

            Console.WriteLine($"Domain: {domain}, Username: {username}, Password: {password}");
            // Add exploit logic here
        }

        // Handle cleanup command
        static void HandleCleanup(string domain, string username, string password, string[] args)
        {
            Console.WriteLine("Running cleanup...");

            // Additional options for cleanup
            if (args.Length > 1)
            {
                string cleanupOption = args[1].ToLower();
                switch (cleanupOption)
                {
                    case "option1":
                        Console.WriteLine("Cleanup option 1 selected.");
                        break;
                    case "option2":
                        Console.WriteLine("Cleanup option 2 selected.");
                        break;
                    default:
                        Console.WriteLine("Invalid cleanup option. Available options: option1, option2.");
                        break;
                }
            }
            else
            {
                Console.WriteLine("No cleanup option provided. Usage: cleanup option1 | option2");
            }

            Console.WriteLine($"Domain: {domain}, Username: {username}, Password: {password}");
            // Add cleanup logic here
        }
    }
}
