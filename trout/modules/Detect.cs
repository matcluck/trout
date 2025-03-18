using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using trout.factories;
using trout.models;

namespace trout
{
    // Controller class for Detect module
    class Detect
    {
        public static bool invoke(string domain) {
            string sysvolPath = $@"\\{domain}\SYSVOL\{domain}\Policies";
            GPO[] gpos = GetGPOsFromSysvol(sysvolPath, domain);

            foreach (GPO gpo in gpos)
            {
                Console.WriteLine(gpo.ToString());
            }
            return true;
        
        }
        // Function to retrieve GPOs from the SYSVOL directory
        static GPO[] GetGPOsFromSysvol(string sysvolPath, string domain)
        {
            // Check if the directory exists
            if (Directory.Exists(sysvolPath))
            {
                // Get all subdirectories in the Policies folder (these are the GPO GUIDs)
                string[] gpoDirectories = Directory.GetDirectories(sysvolPath);

                // Create an array of GPO objects
                var gpos = gpoDirectories.Select(gpoDir => GPOFactory.CreateGPO(gpoDir,domain)).ToArray();

                return gpos;
            }
            else
            {
                Console.WriteLine("SYSVOL path does not exist. Ensure the path is correct.");
                return new GPO[0]; // Return an empty array if SYSVOL path is not found
            }
        }
    }
}
