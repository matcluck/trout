using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace trout.util
{
    class PermissionsUtils
    {
        public class WritePermissionInfo
        {
            public string Path { get; set; }
            public List<string> UsersWithWriteAccess { get; set; } = new List<string>();
            public bool SecurityContextHasWrite { get; set; }
        }

        public static string DecodeAccessMask(int accessMask)
        {
            Dictionary<int, string> rights = new Dictionary<int, string>
        {
            { (int)ActiveDirectoryRights.CreateChild, "CreateChild (0x1)" },
            { (int)ActiveDirectoryRights.DeleteChild, "DeleteChild (0x2)" },
            { (int)ActiveDirectoryRights.ListChildren, "ListChildren (0x4)" },
            { (int)ActiveDirectoryRights.Self, "WriteSelf (0x8)" },
            { (int)ActiveDirectoryRights.ReadProperty, "ReadProperty (0x10)" },
            { (int)ActiveDirectoryRights.WriteProperty, "WriteProperty (0x20)" },
            { (int)ActiveDirectoryRights.DeleteTree, "DeleteTree (0x40)" },
            { (int)ActiveDirectoryRights.ListObject, "ListObject (0x80)" },
            { (int)ActiveDirectoryRights.Delete, "Delete (0x10000)" },
            { (int)ActiveDirectoryRights.ReadControl, "ReadControl (0x20000)" },
            { (int)ActiveDirectoryRights.WriteDacl, "WriteDACL (0x40000)" },
            { (int)ActiveDirectoryRights.WriteOwner, "WriteOwner (0x80000)" },
            { (int)ActiveDirectoryRights.GenericRead, "GenericRead (0x80000000)" },
            { (int)ActiveDirectoryRights.GenericWrite, "GenericWrite (0x40000000)" },
            { (int)ActiveDirectoryRights.GenericExecute, "GenericExecute (0x20000000)" },
            { (int)ActiveDirectoryRights.GenericAll, "GenericAll (0x10000000)" }
        };

            List<string> grantedRights = new List<string>();

            foreach (var right in rights)
            {
                if ((accessMask & right.Key) != 0)
                {
                    grantedRights.Add(right.Value);
                }
            }

            return grantedRights.Count > 0 ? string.Join(", ", grantedRights) : "No Permissions";
        }

        static void processCommonACE(WritePermissionInfo info, CommonAce ace, string securityContextUser)
        {
            if (ace.AceType == AceType.AccessAllowed)  // Only check allow rules
            {
                SecurityIdentifier sid = ace.SecurityIdentifier;
                string principal;
                try
                {
                    principal = sid.Translate(typeof(NTAccount)).ToString(); // Convert SID to name
                }
                catch
                {
                    principal = sid.ToString();
                }
                int accessMask = ace.AccessMask;
                //Console.WriteLine($"Principal {principal}");
                //Console.WriteLine($"AccessMask: 0x{accessMask:X} ({Convert.ToString(accessMask, 2).PadLeft(32, '0')})");
                //Console.WriteLine("Permissions: " + DecodeAccessMask(accessMask) + "\n");

                if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
                {
                    info.UsersWithWriteAccess.Add(principal);

                    if (principal.Equals("NT AUTHORITY\\Authenticated Users"))
                    {
                        info.SecurityContextHasWrite = true;
                    }
                }
                
            }
        

        }

        static void processObjectAce(WritePermissionInfo info, ObjectAce ace, string securityContextUser)
        {
            if (ace.AceType == AceType.AccessAllowed)  // Only check allow rules
            {
                SecurityIdentifier sid = ace.SecurityIdentifier;
                string principal;
                try
                {
                    principal = sid.Translate(typeof(NTAccount)).ToString(); // Convert SID to name
                }
                catch
                {
                    principal = sid.ToString();
                }

                int accessMask = ace.AccessMask;
                //Console.WriteLine($"Principal {principal}");
                //Console.WriteLine($"AccessMask: 0x{accessMask:X} ({Convert.ToString(accessMask, 2).PadLeft(32, '0')})");
                //Console.WriteLine("Permissions: " + DecodeAccessMask(accessMask) + "\n");

                if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
                {
                    info.UsersWithWriteAccess.Add(principal);

                    if (principal.Equals("NT AUTHORITY\\Authenticated Users")) { 
                        info.SecurityContextHasWrite = true;
                    }
                }
            }


        }

        public static WritePermissionInfo GetADObjectWritePermissions(RawSecurityDescriptor rawSD, NetworkCredential credentials)
        {
            WritePermissionInfo info = new WritePermissionInfo();

            string securityContextUser = $"{credentials.Domain}\\{credentials.UserName}";


            foreach (GenericAce ace in rawSD.DiscretionaryAcl)
            {
                if (ace is ObjectAce objectAce)
                {
                    processObjectAce(info, objectAce, securityContextUser);
                }
                else if (ace is CommonAce commonAce)
                {
                    processCommonACE(info, commonAce, securityContextUser);
                }

            }

            return info;
        }

        public static WritePermissionInfo GetBackingStoreWritePermissions(string path, NetworkCredential credentials)
        {
            WritePermissionInfo info = new WritePermissionInfo { Path = path };

            // Get identity string (DOMAIN\username)
            string securityContextUser = $"{credentials.Domain}\\{credentials.UserName}";

            try
            {
                FileSystemSecurity security = File.Exists(path)
                    ? (FileSystemSecurity)File.GetAccessControl(path)  // File security
                    : (FileSystemSecurity)Directory.GetAccessControl(path); // Directory security

                AuthorizationRuleCollection acl = security.GetAccessRules(true, true, typeof(NTAccount));

                foreach (FileSystemAccessRule rule in acl)
                {
                    if ((rule.FileSystemRights & FileSystemRights.WriteData) != 0 &&
                        rule.AccessControlType == AccessControlType.Allow)
                    {
                        string principal = rule.IdentityReference.Value;
                        info.UsersWithWriteAccess.Add(principal);

                        if (principal.Equals("NT AUTHORITY\\Authenticated Users"))
                        {
                            info.SecurityContextHasWrite = true;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Access denied to {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing {path}: {ex.Message}");
            }

            return info;
        
        }
    }
}
