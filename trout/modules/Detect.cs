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
            public List<ADObject> targets { get; set; }
            public List<ADObject> notTargets { get; set; }


            public GPOAndTargets(GPO gpo, List<ADObject> targets, List<ADObject> notTargets)
            {
                this.gpo = gpo;
                this.targets = targets;
                this.notTargets = notTargets;
            }

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


        public static bool invoke(NetworkCredential credentials) {
            string sysvolPath = $@"\\{credentials.Domain}\SYSVOL\{credentials.Domain}\Policies";

            GPO[] gpos;

            try
            {
                gpos = GetGPOsFromSysvol(sysvolPath, credentials.Domain);
            }
            catch (Exception e)
            {
                throw e;
            }
            


            List<GPOAndTargets> exploitableGPOs = new List<GPOAndTargets>();

            foreach (GPO gpo in gpos)
            {
                Console.WriteLine($"\nProcessing: {gpo.ToString()}");
                gpo.checkGPOStorePrincipals(credentials);
                gpo.checkGPOObjectPrincipals(credentials);
                gpo.checkSecurityFilterTargetPrincipals();
                gpo.checkLinkedtoOUs();

                string targetString = "";
                foreach (SecurityPrincipal principal in gpo.securityFilterTargetPrincipals) { targetString = string.IsNullOrEmpty(targetString) ? principal.ToHumanString(credentials.Domain) : $"{principal.ToHumanString(credentials.Domain)},{targetString}"; }

                Console.WriteLine($"Security Filter Target Principals: [{targetString}]");
                //Console.WriteLine($"Modify GPO Store Principals: {string.Join(", ", gpo.modifyGPOStorePrincipals)}");
                //Console.WriteLine($"Modify GPO Object Principals: {string.Join(", ", gpo.modifyGPOObjectPrincipals)}");
                if (gpo.linkedToAtleastOneOU) { foreach (OU ou in gpo.linkedOUs) { Console.WriteLine($"GPO is linked to the following OU: {ou.distinguishedName}"); } }
                else { Console.WriteLine("GPO is not linked"); }

                List<ADObject> exploitableTargets = new List<ADObject>();
                List<ADObject> exploitableButUntargeted = new List<ADObject>();
                
                if (gpo.linkedToAtleastOneOU)
                {
                    List<User> linkedUsers = gpo.getLinkedUsers();
                    List<Computer> linkedComputers = gpo.getLinkedComputers();
                    Console.WriteLine($"Linked Organizational Units contains {linkedUsers.Count} user objects");
                    Console.WriteLine($"Linked Organizational Units contains {linkedComputers.Count} computer objects");

                    if (linkedUsers.Count + linkedComputers.Count > 0)
                    {
                        HashSet<ADObject> uniqueExploitableTargets = new HashSet<ADObject>();

                        Console.WriteLine("Checking if linked objects are targeted by the GPOs security filtering");
                        foreach (SecurityPrincipal sp in gpo.securityFilterTargetPrincipals)
                        {
                            foreach (User linkedUser in linkedUsers)
                            {
                                if (AppSettings.IsVerbose) { Console.WriteLine($"Checking {linkedUser.distinguishedName} against {sp.name}"); }
                                if (PermissionsUtils.CheckPrincipal(credentials.Domain, linkedUser, sp))
                                {
                                    if (AppSettings.IsVerbose) { Console.WriteLine($"{linkedUser.distinguishedName} matches {sp.name} (either matches or child member)"); }
                                    uniqueExploitableTargets.Add(linkedUser);
                                }
                            }

                            foreach (Computer linkedComputer in linkedComputers)
                            {
                                if (AppSettings.IsVerbose) { Console.WriteLine($"Checking {linkedComputer.distinguishedName} against {sp.name}"); }
                                if (PermissionsUtils.CheckPrincipal(credentials.Domain, linkedComputer, sp))
                                {
                                    if (AppSettings.IsVerbose) { Console.WriteLine($"{linkedComputer.distinguishedName} matches {sp.name} (either matches or child member)"); }
                                    uniqueExploitableTargets.Add(linkedComputer);
                                }

                            }
                        }
                        exploitableTargets.AddRange(uniqueExploitableTargets);
                        exploitableButUntargeted.AddRange(linkedUsers.Except(exploitableTargets));
                        exploitableButUntargeted.AddRange(linkedComputers.Except(exploitableTargets));
                    }




                }
                string identity = string.IsNullOrEmpty(credentials.UserName) ? WindowsIdentity.GetCurrent().Name : credentials.UserName;
                Console.WriteLine($"Current security principal ({identity}) can modify backing store: {gpo.backingStoreModifiable}");
                Console.WriteLine($"Current security principal ({identity}) can modify AD object: {gpo.adObjectModifiable}");

                // We need all three primitives to be able to exploit
                if (gpo.backingStoreModifiable && gpo.adObjectModifiable && gpo.linkedToAtleastOneOU)
                {
                    exploitableGPOs.Add(new GPOAndTargets(gpo, exploitableTargets, exploitableButUntargeted));
                }
            }

            foreach (GPOAndTargets gpoAndTargets in exploitableGPOs)
            {
                int exploitableComputerTargets = gpoAndTargets.targets.OfType<Computer>().ToList<Computer>().Count;
                int exploitableUserTargets = gpoAndTargets.targets.OfType<User>().ToList<User>().Count;
                int exploitableComputerNonTargets = gpoAndTargets.notTargets.OfType<Computer>().ToList<Computer>().Count;
                int exploitableUserNonTargets = gpoAndTargets.notTargets.OfType<User>().ToList<User>().Count;


                Console.WriteLine();

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
                throw new ApplicationException($"SYSVOL path ({sysvolPath}) does not exist. Ensure the path is correct.");
            }
        }
    }
}
