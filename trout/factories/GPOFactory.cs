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
                SearchResult gpoObject = GetADObject(gpoGuid, domain);

                if (gpoObject != null)
                {
                    string displayName = getDisplayName(gpoObject);
                    RawSecurityDescriptor SDDL = getSDDL(gpoObject);
                    int version = getVersion(gpoObject);

                    // Return a new GPO object
                    return new GPO(gpoGuid, gpoDir, displayName, SDDL, version);
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

        private static SearchResult GetADObject(string gpoGuid, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);
                // Connect to the Active Directory and search under the System\Policies container
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    // Set the base search location to the System\Policies container in the domain
                    searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/CN=Policies,CN=System,{ldapDomainString}");

                    // Set the filter to search for a GPO with the given GUID
                    string ldapFilter = $"(&(objectClass=groupPolicyContainer)(cn={gpoGuid}))";
                    searcher.Filter = ldapFilter;

                    // Load all properties
                    searcher.PropertiesToLoad.Clear();

                    searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner | SecurityMasks.Group;

                    // Perform the search
                    SearchResult result = searcher.FindOne();

                    if (result != null)
                    {
                        return result;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle any errors that occur during the AD query
                return null;
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
