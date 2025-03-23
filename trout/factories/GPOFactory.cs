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
        // Factory method to create a GPO object
        public static GPO CreateGPO(string gpoDir, string domain)
        {
            // Extract the GPO GUID (folder name)
            string gpoGuid = Path.GetFileName(gpoDir);
            
            // If the path contains a "gpt.ini" file
            if (FSUtils.checkGPTFile(gpoDir)) {

                // Retrieve the AD object associated with the GPO directory from AD via LDAP
                SearchResult gpoObject = LDAPUtils.GetADGPOObject(gpoGuid, domain);

                if (gpoObject != null)
                {
                    string displayName = getDisplayName(gpoObject);
                    if (displayName == "")
                    {
                        throw new ArgumentException($"Invalid displayName for the ${gpoGuid} GPO.");
                    }

                    RawSecurityDescriptor SDDL = getSDDL(gpoObject);
                    if (SDDL == null)
                    {
                        throw new ArgumentException($"Invalid SDDL for the ${displayName} GPO.");
                    }
                    
                    int version = getVersion(gpoObject);
                    if (version == -1)
                    {
                        throw new ArgumentException($"Invalid version number for the ${displayName} GPO.");
                    }

                    List<OU> linkedOUs = LDAPUtils.getLinkedOUs(gpoGuid, domain);

                    // Create and return a new GPO object
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

        // Retrieves GPO version number from search result
        private static int getVersion(SearchResult gpoObject)
        {
            if (gpoObject.Properties["versionNumber"] != null && gpoObject.Properties["versionNumber"].Count > 0)
            {
                int version = (int)gpoObject.Properties["versionNumber"][0];
                return version;
            }
            else
            {
                return -1; // could not resolve version number
            }
        }

        // Retrieves GPO SDDL from search result
        private static RawSecurityDescriptor getSDDL(SearchResult gpoObject)
        {
            if (gpoObject.Properties["nTSecurityDescriptor"] != null && gpoObject.Properties["nTSecurityDescriptor"].Count > 0)
            {
                byte[] sd = (byte[])gpoObject.Properties["nTSecurityDescriptor"][0];
                return new RawSecurityDescriptor(sd, 0);
            }
            else
            {
                return null; // could not resolve SDDL
            }
        }

        // 
        private static String getDisplayName(SearchResult gpoObject) {
            if (gpoObject.Properties["displayName"] != null && gpoObject.Properties["displayName"].Count > 0)
            {
                return gpoObject.Properties["displayName"][0].ToString();
            }
            else
            {
                return ""; // could not resolve display name
            }
        }



        


    }
}
