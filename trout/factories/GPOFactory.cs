using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;
using trout.models;
using trout.util;

namespace trout.factories
{
    public static class GPOFactory
    {
        // Factory method to create GPO object
        public static GPO CreateGPO(string gpoDir, string domain)
        {
            // Extract the GPO GUID (folder name)
            string gpoGuid = Path.GetFileName(gpoDir);
            
            if (checkGPTFile(gpoDir)) {
                SearchResult gpoObject = LDAPUtils.GetADGPOObject(gpoGuid, domain);

                if (gpoObject != null)
                {
                    string displayName = getDisplayName(gpoObject);
                    RawSecurityDescriptor SDDL = getSDDL(gpoObject);
                    int version = getVersion(gpoObject);

                    List<OU> linkedOUs = LDAPUtils.getLinkedOUs(gpoGuid, domain);

                    // Return a new GPO object
                    return new GPO(gpoGuid, gpoDir, displayName, SDDL, version, linkedOUs);
                }
                else
                {
                    throw new ArgumentException("Invalid AD object.");

                }

            }
            else
            {
                throw new ArgumentException("Invalid gpt.ini file.");
            }
            
        }


        private static int getVersion(SearchResult gpoObject)
        {
            if (gpoObject.Properties["versionNumber"] != null && gpoObject.Properties["versionNumber"].Count > 0)
            {
                int version = (int)gpoObject.Properties["versionNumber"][0];
                return version;
            }
            else
            {
                return -1;
            }
        }
        private static RawSecurityDescriptor getSDDL(SearchResult gpoObject)
        {
            if (gpoObject.Properties["nTSecurityDescriptor"] != null && gpoObject.Properties["nTSecurityDescriptor"].Count > 0)
            {
                byte[] sd = (byte[])gpoObject.Properties["nTSecurityDescriptor"][0];
                return new RawSecurityDescriptor(sd, 0);
            }
            else
            {
                return null;
            }
        }

        private static String getDisplayName(SearchResult gpoObject) {
            if (gpoObject.Properties["displayName"] != null && gpoObject.Properties["displayName"].Count > 0)
            {
                return gpoObject.Properties["displayName"][0].ToString();
            }
            else
            {
                return "GPO Name not found.";
            }
        }



        private static bool checkGPTFile(string gpoDirectory)
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
