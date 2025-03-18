using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using trout.factories;
using trout.models;

namespace trout
{
    // Controller class for Detect module
    class Detect
    {
        public static bool invoke(NetworkCredential credentials) {
            string domain = credentials.Domain;
            string sysvolPath = $@"\\{domain}\SYSVOL\{domain}\Policies";
            GPO[] gpos = GetGPOsFromSysvol(sysvolPath, domain);
            List<GPO> exploitable = new List<GPO>();

            foreach (GPO gpo in gpos)
            {
                Console.WriteLine($"\nProcessing: {gpo.ToString()}");
                gpo.checkGPOStorePrincipals(credentials);
                gpo.checkGPOObjectPrincipals(credentials);
                gpo.checkSecurityFilterTargetPrincipals();
                Console.WriteLine($"Security Filter Target Principals: {string.Join(", ", gpo.securityFilterTargetPrincipals)}");
                Console.WriteLine($"Modify GPO Store Principals: {string.Join(", ", gpo.modifyGPOStorePrincipals)}");
                Console.WriteLine($"Modify GPO Object Principals: {string.Join(", ", gpo.modifyGPOObjectPrincipals)}");
                Console.WriteLine($"Running context ({credentials.Domain}\\{credentials.UserName}) can modify backing store: {gpo.backingStoreModifiable}");
                Console.WriteLine($"Running context ({credentials.Domain}\\{credentials.UserName}) can modify AD object: {gpo.adObjectModifiable}");

                if (gpo.backingStoreModifiable && gpo.adObjectModifiable)
                {
                    exploitable.Add( gpo );
                }
            }

            foreach (GPO gpo in exploitable)
            {
                Console.WriteLine($"\n!!!!! {gpo.ToString()} is exploitable with {gpo.securityFilterTargetPrincipals.Count} targets!!!!!");
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
