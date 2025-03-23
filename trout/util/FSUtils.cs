using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using trout.factories;
using trout.models;

namespace trout.util
{
    public class FSUtils
    {
        // Function to retrieve GPOs from the SYSVOL directory
        public static GPO[] GetGPOsFromSysvol(string sysvolPath, string domain)
        {
            // Check if the directory exists
            if (Directory.Exists(sysvolPath))
            {
                // Get all subdirectories in the Policies folder (these are the GPO GUIDs)
                string[] gpoDirectories = Directory.GetDirectories(sysvolPath);

                // Create an array of GPO objects
                var gpos = gpoDirectories.Select(gpoDir => GPOFactory.CreateGPO(gpoDir, domain)).ToArray();

                return gpos;
            }
            else
            {
                throw new ApplicationException($"SYSVOL path ({sysvolPath}) does not exist. Ensure the path is correct.");
            }
        }

        // Check the provided gpoDirectory path for the presence of a GPO "gpt.ini" file
        public static bool checkGPTFile(string gpoDirectory)
        {
            string gptIniPath = Path.Combine(gpoDirectory, "gpt.ini");

            if (File.Exists(gptIniPath))
            {
                return true;
            }

            return false;
        }
    }
}
