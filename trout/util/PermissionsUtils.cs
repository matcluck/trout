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
        // Container class that contains results from various PermissionsUtils functions
        public class WritePermissionInfo
        {
            public string Path { get; set; }
            public List<string> UsersWithWriteAccess { get; set; } = new List<string>();
        }

        // Function to output a Security Descriptor Definition Language (SDDL) string in a human readable format
        public static string DecodeAccessMask(int accessMask)
        {
            Dictionary<int, string> rights = new Dictionary<int, string> {
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

        // Function to process a supplied ACE, and determine whether the ACE provides Write privileges for the principal
        static void processCommonACE(WritePermissionInfo info, CommonAce ace)
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
                    principal = sid.ToString(); // If this fails, just return the supplied sid value.
                }
                int accessMask = ace.AccessMask;
                
                if (AppSettings.IsVerbose)
                {
                    Console.WriteLine($"Principal {principal}");
                    Console.WriteLine($"AccessMask: 0x{accessMask:X} ({Convert.ToString(accessMask, 2).PadLeft(32, '0')})");
                    Console.WriteLine("Permissions: " + DecodeAccessMask(accessMask) + "\n");
                }

                if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
                {
                    info.UsersWithWriteAccess.Add(principal);
                }
            }
        }

        // Function to process a supplied ACE, and determine whether the ACE provides Write privileges for the principal
        // This feels like code reuse 🤔
        static void processObjectAce(WritePermissionInfo info, ObjectAce ace)
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

                if (AppSettings.IsVerbose)
                {
                    Console.WriteLine($"Principal {principal}");
                    Console.WriteLine($"AccessMask: 0x{accessMask:X} ({Convert.ToString(accessMask, 2).PadLeft(32, '0')})");
                    Console.WriteLine("Permissions: " + DecodeAccessMask(accessMask) + "\n");
                }

                if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
                {
                    info.UsersWithWriteAccess.Add(principal);
                }
            }
        }

        // Function that returns all principals with write for the specified SDDL
        public static WritePermissionInfo GetADObjectWritePermissions(RawSecurityDescriptor rawSD, NetworkCredential credentials)
        {
            WritePermissionInfo info = new WritePermissionInfo();


            foreach (GenericAce ace in rawSD.DiscretionaryAcl)
            {
                if (ace is ObjectAce objectAce)
                {
                    processObjectAce(info, objectAce);
                }
                else if (ace is CommonAce commonAce)
                {
                    processCommonACE(info, commonAce);
                }

            }

            return info;
        }

        // Function that determines the write permissions for the GPOs backing store (SYSVOL)
        public static WritePermissionInfo GetBackingStoreWritePermissions(string path, NetworkCredential credentials)
        {
            WritePermissionInfo info = new WritePermissionInfo { Path = path };

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

        // Function to determine whether the specified principalName matches the provided userDistinguishedName
        private static bool IsUserThePrincipal(string userDistinguishedName, string principalName)
        {
            // For common principals (like "NT AUTHORITY\SYSTEM" or SID), check if the user is the same
            return userDistinguishedName.Equals(principalName, StringComparison.OrdinalIgnoreCase);
        }

        // Check whether the ADObject is a member of the specified principal (e.g. whether the provided object is a member of a domain group)
        public static bool CheckPrincipal(string domain, ADObject obj, SecurityPrincipal principal)
        {
            // e.g. Domain Users, Domain Computers, Custom Domain Group, etc
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
                // Authenticated Users, Everyone, etc.
                return IsInCommonPrincipal(obj, principal.name);
            }
        }

        // Check whether the ADObject is in a domain group, or nested domain group (recursion)
        private static bool IsObjInDomainGroup(string domain, ADObject obj, string groupIdentifier)
        {
            try
            {
                // Speed up resolution when the groupIdentifier is for Domain Users or Domain Computers
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
                    // Retrieve the User from AD (also handles computers as they're a type of user (computer account))
                    UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.DistinguishedName, obj.distinguishedName);

                    if (user == null)
                        return false;

                    GroupPrincipal group = null;

                    // Try find group by GUID
                    if (Guid.TryParse(groupIdentifier, out _))
                        group = GroupPrincipal.FindByIdentity(context, IdentityType.Guid, groupIdentifier);
                    // Try find group by SID (e.g. S-1-5-domain-513)
                    else if (IsValidSid(groupIdentifier))
                    {
                        group = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, groupIdentifier);
                    }
                    // Else, try find the group by DistinguishedName
                    else
                        group = GroupPrincipal.FindByIdentity(context, IdentityType.DistinguishedName, groupIdentifier);

                    if (group == null)
                        return false;

                    // Checks whether the ADObject is a member of the group (contains base case and recursive call)
                    return IsMemberOfGroupRecursive(user, group);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking group membership: {ex.Message}");
                return false;
            }
        }
        // Helper method to check if the identifier is a valid SID
        static bool IsValidSid(string sidString)
        {
            try
            {
                new SecurityIdentifier(sidString);
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Handles determining if a user is a member of a group with recursion (Todo: Test)
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

        // Function to determine if user belongs to a common principal
        private static bool IsInCommonPrincipal(ADObject obj, string commonPrincipal)
        {
            return commonPrincipal.Contains("Authenticated Users")
                   || commonPrincipal.Contains("Everyone");
        }

    }
}
