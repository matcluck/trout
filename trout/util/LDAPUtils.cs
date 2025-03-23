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

    // This class contains various LDAP functions to interact with AD's LDAP store.
    // TODO: Reduce repeating code and consolidate functionality
    class LDAPUtils
    {
        // Retrieves a GPO Object from AD by specified GPO GUID
        public static SearchResult GetADGPOObject(string gpoGuid, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);
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
                return null;
            }
        }

        // Function to get a List of OUs that are linked to the specified GPO
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

        // Function to get a list of ADObjects that are children of the OU (for example, users and computers that are nested within the OU)
        public static List<ADObject> getOUChildren(string ouPath, string domain)
        {
            List<ADObject> results = new List<ADObject>();
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ouPath))
                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ouPath}");

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
                if (AppSettings.IsVerbose)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }

            return results;
        }

        // Function to resolve a provided SID to sAMAccountName using LDAP
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

        // Function to resolve sAMAccountName to SID via LDAP
        public static string ResolveNameToSidUsingLdap(string samaccountname, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);

                // Set up the LDAP connection
                DirectoryEntry entry = new DirectoryEntry(ldapDomainString);
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ldapDomainString}");

                searcher.Filter = $"(sAMAccountName={samaccountname})";
                searcher.PropertiesToLoad.Add("objectSid");

                // Perform the search
                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                    SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                    return sid.Value;
                }
                else
                {
                    throw new Exception("sAMAccountName not found in Active Directory.");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to resolve sAMAccountName to name using LDAP.", ex);
            }
        }

        // Function to retrieve properties and return an ADObject object from a provided sAMAccountName
        public static ADObject GetADObjectFromSamAccountName(string samaccountname, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);

                // Set up the LDAP connection
                DirectoryEntry entry = new DirectoryEntry(ldapDomainString);
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ldapDomainString}");

                searcher.Filter = $"(sAMAccountName={samaccountname})";
                searcher.PropertiesToLoad.Add("objectSid");
                searcher.PropertiesToLoad.Add("sAMAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");

                // Perform the search
                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    ADObject retObj = new ADObject();
                    retObj.distinguishedName = (string)result.Properties["distinguishedName"][0];
                    byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                    SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                    retObj.name = samaccountname;
                    retObj.sid = sid.Value;
                    return retObj;
                }
                else
                {
                    throw new Exception("sAMAccountName not found in Active Directory.");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to resolve sAMAccountName using LDAP.", ex);
            }
        }

        public static string[] getObjectClassesFromSID(string sid, string domain)
        {
            try
            {
                string ldapDomainString = StringUtils.GetLDAPFormattedDomainName(domain);

                // Set up the LDAP connection
                DirectoryEntry entry = new DirectoryEntry(ldapDomainString);
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.SearchRoot = new DirectoryEntry($"LDAP://{domain}/{ldapDomainString}");

                searcher.Filter = $"(objectSid={sid})";
                searcher.PropertiesToLoad.Add("objectClass");

                // Perform the search
                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    ADObject retObj = new ADObject();
                    var objectClasses = result.Properties["objectClass"];
                    return objectClasses.Cast<string>().ToArray();
                }
                else
                {
                    throw new Exception("SID not found in Active Directory.");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to resolve SID using LDAP.", ex);
            }
        }
    }
}
