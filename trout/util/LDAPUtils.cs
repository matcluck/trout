using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using trout.models;

namespace trout.util
{
    class LDAPUtils
    {

        public static SearchResult GetADGPOObject(string gpoGuid, string domain)
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

        public static List<OU> getLinkedOUs(string gpoGuid, string domain)
        {
            string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);
            List<OU> linkedOUs = new List<OU>();
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ldapDomainString))
                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ldapDomainString}");

                    // Search for all objects with a gpLink attribute containing the GPO GUID
                    searcher.Filter = $"(gPLink=*{gpoGuid}*)";
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("gPLink");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string distinguishedName = result.Properties["distinguishedName"][0].ToString();
                        OU ou = new OU(distinguishedName, domain);
                        linkedOUs.Add(ou);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            return linkedOUs;
        }

        public static List<ADObject> getOUChildren(string ouPath, string domain)
        {
            List<ADObject> results = new List<ADObject>();
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ouPath))
                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ouPath}");

                    // Search for all objects with a gpLink attribute containing the GPO GUID
                    searcher.Filter = "(|(objectClass=user)(objectClass=computer))";
                    searcher.PropertiesToLoad.Add("distinguishedName");
                    searcher.PropertiesToLoad.Add("objectClass");
                    searcher.PropertiesToLoad.Add("objectSid");
                    searcher.PropertiesToLoad.Add("name");


                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string distinguishedName = result.Properties["distinguishedName"][0].ToString();
                        string sid = new SecurityIdentifier((byte[])result.Properties["objectSid"][0], 0).ToString();
                        var objectClasses = result.Properties["objectClass"];
                        string name = result.Properties["name"][0].ToString();

                        // this ordering is critical (computer before user), as a computer object is also a user object
                        if (objectClasses.Contains("computer"))
                        {
                            Computer computer = new Computer();
                            computer.distinguishedName = distinguishedName;
                            computer.sid = sid;
                            computer.name = name;
                            results.Add(computer);
                        }
                        else if (objectClasses.Contains("user"))
                        {
                            User user = new User();
                            user.distinguishedName = distinguishedName;
                            user.sid = sid;
                            user.name = name;
                            results.Add(user);

                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            return results;
        }

        public static string ResolveSidToNameUsingLdap(string sid, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);

                // Set up the LDAP connection
                DirectoryEntry entry = new DirectoryEntry(ldapDomainString);
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ldapDomainString}");


                // Set the filter to search for the SID in the Active Directory
                SecurityIdentifier securityIdentifier = new SecurityIdentifier(sid);


                searcher.Filter = $"(objectSid={sid})";
                searcher.PropertiesToLoad.Add("name");
                searcher.PropertiesToLoad.Add("sAMAccountName");

                // Perform the search
                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    // Return the sAMAccountName or other property like cn if needed
                    if (string.IsNullOrEmpty(result.Properties["sAMAccountName"][0].ToString())) {
                        return result.Properties["name"][0].ToString();
                    }
                    else
                    {
                        return result.Properties["sAMAccountName"][0].ToString();
                    }
                        
                }
                else
                {
                    throw new Exception("SID not found in Active Directory.");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to resolve SID to name using LDAP.", ex);
            }
        }
    }
}
