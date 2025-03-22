using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using trout.models;

namespace trout.util
{
    class PermissionsUtils
    {
        public class WritePermissionInfo
        {
            public string Path { get; set; }
            public List<string> UsersWithWriteAccess { get; set; } = new List<string>();
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
        private static bool IsUserThePrincipal(string userDistinguishedName, string principalName)
        {
            // For common principals (like "NT AUTHORITY\SYSTEM" or SID), check if the user is the same
            return userDistinguishedName.Equals(principalName, StringComparison.OrdinalIgnoreCase);
        }

        public static bool CheckPrincipal(string domain, ADObject obj, SecurityPrincipal principal)
        {
            if (principal.IsDomainPrincipal)
            {
                if (IsUserThePrincipal(obj.sid, principal.name))
                {
                    return true;
                }
                else
                {
                    return IsObjInDomainGroup(domain, obj, principal.name);
                }
            }
            else
            {
                return IsInCommonPrincipal(obj, principal.name);
            }
        }

        // Method 1: Check domain group membership recursively
        private static bool IsObjInDomainGroup(string domain, ADObject obj, string groupIdentifier)
        {
            try
            {
                if (obj is Computer)
                {
                    string reDomainComputers = @"^S-1-5-21-\d{1,}-\d{1,}-\d{1,}-515";
                    if (Regex.IsMatch(groupIdentifier, reDomainComputers)) { return true; } // If the groupIdentifier is the SID for the Domain Computers group, we can assume that the computer is in the Domain Computers group.
                }
                else if (obj is User)
                {
                    string reDomainUsers = @"^S-1-5-21-\d{1,}-\d{1,}-\d{1,}-513$";
                    if (Regex.IsMatch(groupIdentifier, reDomainUsers)) { return true; } // If the groupIdentifier is the SID for the Domain Users group, we can assume that the user is in the Domain Users group.
                }
               

                using (PrincipalContext context = new PrincipalContext(ContextType.Domain, domain))
                {
                    UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.DistinguishedName, obj.distinguishedName);

                    if (user == null)
                        return false;

                    GroupPrincipal group = null;

                    // Check if the group is specified as a GUID
                    if (Guid.TryParse(groupIdentifier, out _))
                        group = GroupPrincipal.FindByIdentity(context, IdentityType.Guid, groupIdentifier);
                    else
                        group = GroupPrincipal.FindByIdentity(context, IdentityType.DistinguishedName, groupIdentifier);

                    if (group == null)
                        return false;

                    return IsMemberOfGroupRecursive(user, group);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking group membership: {ex.Message}");
                return false;
            }
        }

        private static bool IsMemberOfGroupRecursive(Principal user, GroupPrincipal group)
        {
            if (group.Members.Contains(user))
                return true;

            foreach (Principal member in group.Members)
            {
                if (member is GroupPrincipal nestedGroup && IsMemberOfGroupRecursive(user, nestedGroup))
                    return true;
            }

            return false;
        }

        // Method 2: Check if user belongs to a common principal
        private static bool IsInCommonPrincipal(ADObject obj, string commonPrincipal)
        {
            return commonPrincipal.Contains("Authenticated Users")
                   || commonPrincipal.Contains("Everyone");
        }

    }
}
