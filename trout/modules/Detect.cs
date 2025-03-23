using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using trout.factories;
using trout.models;
using trout.util;

namespace trout
{
    // Controller class for Detect module
    class Detect
    {
        class GPOAndTargets
        {
            public GPO gpo { get; set; }
            public List<ADObject> targets { get; set; } // ADObject's that the GPO currently targets
            public List<ADObject> notTargets { get; set; } // ADObject's that are not currently targets but are contained within linked OUs (can become targets through modification of the GPO's security filtering).

            // Container class that associates a GPO with ADObject targets
            public GPOAndTargets(GPO gpo, List<ADObject> targets, List<ADObject> notTargets)
            {
                this.gpo = gpo;
                this.targets = targets;
                this.notTargets = notTargets;
            }


            // Function that returns a comma-separated string
            public string getTargetsString(string objectType)
            {
                string result = "";
                if (objectType == "computer")
                {
                    result = string.Join(",", this.targets.OfType<Computer>().ToList());

                }
                else if (objectType == "user")
                {
                    result = string.Join(",", this.targets.OfType<User>().ToList());

                }
                return result;
            }

            // Function that returns a comma-separated string
            public string getNotTargetsString(string objectType)
            {
                string result = "";
                if (objectType == "computer")
                {
                    result = string.Join(",", this.notTargets.OfType<Computer>().ToList());

                }
                else if (objectType == "user")
                {
                    result = string.Join(",", this.notTargets.OfType<User>().ToList());

                }
                return result;
            }
        }

        // Function to invoke the Detect module/functionality
        public static bool invoke(NetworkCredential credentials, string userSuppliedPrincipal = "") {
            // Create expected SYSVOL path using the domain name contained within the credentials object
            string sysvolPath = $@"\\{credentials.Domain}\SYSVOL\{credentials.Domain}\Policies";

            GPO[] gpos;
            List<GPOAndTargets> exploitableGPOs = new List<GPOAndTargets>();

            // Populate gpos array with GPOs retrieved from SYSVOL
            try
            {
                gpos = FSUtils.GetGPOsFromSysvol(sysvolPath, credentials.Domain);
            }
            catch (Exception e)
            {
                throw e;
            }

            // Process each GPO
            foreach (GPO gpo in gpos)
            {
                Console.WriteLine($"\nProcessing: {gpo.ToString()}");
                gpo.checkGPOStorePrincipals(credentials);
                gpo.checkGPOObjectPrincipals(credentials);
                gpo.checkSecurityFilterTargetPrincipals();
                gpo.checkLinkedtoOUs();

                // Create a comma-separated list of objects targeted by the GPOs security filtering
                string targetString = "";
                foreach (SecurityPrincipal principal in gpo.securityFilterTargetPrincipals) { targetString = string.IsNullOrEmpty(targetString) ? principal.ToHumanString(credentials.Domain) : $"{principal.ToHumanString(credentials.Domain)},{targetString}"; }

                Console.WriteLine($"Security Filter Target Principals: [{targetString}]");

                // If the GPO is currently associated with at least one Organizational Unit
                // Print list of linked OUs
                if (gpo.linkedToAtleastOneOU) { foreach (OU ou in gpo.linkedOUs) { Console.WriteLine($"GPO is linked to the following OU: {ou.distinguishedName}"); } }
                else { Console.WriteLine("GPO is not linked"); }

                List<ADObject> exploitableTargets = new List<ADObject>();
                List<ADObject> exploitableButUntargeted = new List<ADObject>();
                
                if (gpo.linkedToAtleastOneOU)
                {
                    List<User> linkedUsers = gpo.getLinkedUsers(); // Retrieve a list of all users that are contained within linked OUs
                    List<Computer> linkedComputers = gpo.getLinkedComputers();// Retrieve a list of all computers that are contained within linked OUs
                    Console.WriteLine($"Linked Organizational Units contains {linkedUsers.Count} user objects");
                    Console.WriteLine($"Linked Organizational Units contains {linkedComputers.Count} computer objects");

                    // If linked objects are present
                    if (linkedUsers.Count + linkedComputers.Count > 0)
                    {
                        // Using a HashSet here instead of a list to avoid duplicates
                        HashSet<ADObject> uniqueExploitableTargets = new HashSet<ADObject>();

                        Console.WriteLine("Checking if linked objects are targeted by the GPOs security filtering");
                        foreach (SecurityPrincipal sp in gpo.securityFilterTargetPrincipals)
                        {
                            foreach (User linkedUser in linkedUsers)
                            {
                                if (AppSettings.IsVerbose) { Console.WriteLine($"Checking {linkedUser.distinguishedName} for membership in {sp.name}"); }
                                if (PermissionsUtils.CheckPrincipal(credentials.Domain, linkedUser, sp))
                                {
                                    if (AppSettings.IsVerbose) { Console.WriteLine($"{linkedUser.distinguishedName} is a member of {sp.name} (either matches or child member)"); }
                                    uniqueExploitableTargets.Add(linkedUser);
                                }
                            }

                            foreach (Computer linkedComputer in linkedComputers)
                            {
                                if (AppSettings.IsVerbose) { Console.WriteLine($"Checking {linkedComputer.distinguishedName} for membership in {sp.name}"); }
                                if (PermissionsUtils.CheckPrincipal(credentials.Domain, linkedComputer, sp))
                                {
                                    if (AppSettings.IsVerbose) { Console.WriteLine($"{linkedComputer.distinguishedName} is a member of {sp.name} (either matches or child member)"); }
                                    uniqueExploitableTargets.Add(linkedComputer);
                                }

                            }
                        }
                        exploitableTargets.AddRange(uniqueExploitableTargets);
                        exploitableButUntargeted.AddRange(linkedUsers.Except(exploitableTargets)); // Add the users that were not exploitable targets
                        exploitableButUntargeted.AddRange(linkedComputers.Except(exploitableTargets)); // Add the computers that were not exploitable targets
                    }
                }

                bool backingStoreModifiable = false;
                bool adObjectModifiable = false;

                // A list of identities to check for write to the GPO object
                List<string> checkIdentities = new List<string>();
                checkIdentities.Add("Authenticated Users");
                checkIdentities.Add("Everyone");

                // Used to handle if the user supplys a principal to check whether they can modify the GPO object
                string userSuppliedSid = "";
                if (!(string.IsNullOrEmpty(userSuppliedPrincipal)))
                {
                    userSuppliedSid = LDAPUtils.ResolveNameToSidUsingLdap(userSuppliedPrincipal, credentials.Domain);
                }
                bool userSuppliedCanModifyBackingStore = false;

                // Check if the principals that can modify the GPO backing store contain the identities listed in checkIdentities, or the user specified principal
                foreach (SecurityPrincipal principal in gpo.modifyGPOStorePrincipals)
                {
                    foreach (string checkIdentity in checkIdentities)
                    {
                        if (principal.name.Contains(checkIdentity))
                        {
                            backingStoreModifiable = true;
                            Console.WriteLine($"{checkIdentity} identity can modify the GPOs backing store!");
                        }
                    }

                    if (!(string.IsNullOrEmpty(userSuppliedSid)) && !userSuppliedCanModifyBackingStore)
                    {
                        ADObject queryObject = LDAPUtils.GetADObjectFromSamAccountName(userSuppliedPrincipal, credentials.Domain);

                        if (PermissionsUtils.CheckPrincipal(credentials.Domain, queryObject, principal))
                        {
                            backingStoreModifiable = true;
                            Console.WriteLine($"User supplied identity ({userSuppliedPrincipal}) can modify the GPOs backing store!");
                            userSuppliedCanModifyBackingStore = true;
                        }

                    }
                }

                bool userSuppliedCanModifyADObject = false;

                // Check if the principals that can modify the AD object contain the identities listed in checkIdentities, or the user specified principal
                foreach (SecurityPrincipal principal in gpo.modifyGPOObjectPrincipals)
                {
                    foreach (string checkIdentity in checkIdentities)
                    {
                        if (principal.name.Contains(checkIdentity))
                        {
                            adObjectModifiable = true;
                            Console.WriteLine($"{checkIdentity} identity can modify the GPOs AD object!");
                        }
                    }

                    if (!(string.IsNullOrEmpty(userSuppliedSid)) && userSuppliedCanModifyADObject)
                    {
                        ADObject queryObject = LDAPUtils.GetADObjectFromSamAccountName(userSuppliedPrincipal, credentials.Domain);

                        if (PermissionsUtils.CheckPrincipal(credentials.Domain, queryObject, principal))
                        {
                            backingStoreModifiable = true;
                            Console.WriteLine($"User supplied identity ({userSuppliedPrincipal}) can modify the GPOs AD object!");
                            userSuppliedCanModifyADObject = true;
                        }

                    }
                }

                // If all three primitives are met (backing store modifiable, AD object modifiable, and linked to at least one OU), we can most likely exploit the GPO (if the linked OU/OUs contain at least one active user or computer object)
                if (backingStoreModifiable && adObjectModifiable && gpo.linkedToAtleastOneOU)
                {
                    exploitableGPOs.Add(new GPOAndTargets(gpo, exploitableTargets, exploitableButUntargeted));
                }
            }

            // Process each exploitableGPO and determine which computers and users are currently targeted, or can be targeted
            foreach (GPOAndTargets gpoAndTargets in exploitableGPOs)
            {
                int exploitableComputerTargets = gpoAndTargets.targets.OfType<Computer>().ToList<Computer>().Count;
                int exploitableUserTargets = gpoAndTargets.targets.OfType<User>().ToList<User>().Count;
                int exploitableComputerNonTargets = gpoAndTargets.notTargets.OfType<Computer>().ToList<Computer>().Count;
                int exploitableUserNonTargets = gpoAndTargets.notTargets.OfType<User>().ToList<User>().Count;


                Console.WriteLine(); // Used for formatting stdout

                if (exploitableComputerTargets > 0)
                {
                    Console.WriteLine($"***** {gpoAndTargets.gpo.ToString()} is currently exploitable with {exploitableComputerTargets} computer target/s: [{gpoAndTargets.getTargetsString("computer")}] *****");
                }
                if (exploitableUserTargets > 0) {
                    Console.WriteLine($"***** {gpoAndTargets.gpo.ToString()} is currently exploitable with {exploitableUserTargets} user target/s: [{gpoAndTargets.getTargetsString("user")}] *****");

                }
                if (exploitableComputerNonTargets > 0)
                {
                    Console.WriteLine($"***** Security filtering for {gpoAndTargets.gpo.ToString()} can be modified, enabling up to {exploitableComputerNonTargets} additional exploitable computer target/s: [{gpoAndTargets.getNotTargetsString("computer")}] *****");
                }
                if (exploitableUserNonTargets > 0) {
                    Console.WriteLine($"***** Security filtering for {gpoAndTargets.gpo.ToString()} can be modified, enabling up to {exploitableUserNonTargets} additional exploitable user target/s: [{gpoAndTargets.getNotTargetsString("user")}] *****");
                }

                if (exploitableComputerTargets + exploitableUserTargets + exploitableComputerNonTargets + exploitableUserNonTargets == 0)
                {
                    Console.WriteLine($"***** {gpoAndTargets.gpo.ToString()} is not currently exploitable as the GPOs linked OUs contained no user or computer objects :( *****");
                }
            }

            return true;
        
        }
        
    }
}
