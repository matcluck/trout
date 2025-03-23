using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using trout.util;
using static trout.util.PermissionsUtils;

namespace trout.models
{
    public class GPO
    {
        string guid { get; set; }
        string name { get; set; }
        string filePath { get; set; }
        RawSecurityDescriptor sd { get; set; }
        int version { get; set; }
        public List<SecurityPrincipal> modifyGPOObjectPrincipals { get; set; }
        public List<SecurityPrincipal> modifyGPOStorePrincipals { get; set;  }
        public List<SecurityPrincipal> securityFilterTargetPrincipals { get; set; }
        public bool backingStoreModifiable { get; set; }
        public bool adObjectModifiable { get; set; }
        public List<OU> linkedOUs {  get; set; }
        public bool linkedToAtleastOneOU {  get; set; }
        
        // Override the default ToString() method with a custom implementation
        override public string ToString()
        {
            return $"{name}";
        }

        public GPO(string guid, string filepath, string name, RawSecurityDescriptor sd, int version, List<OU> linkedOUs)
        {
            this.guid = guid;
            this.filePath = filepath;
            this.name = name;
            this.sd = sd;
            this.version = version;
            this.modifyGPOObjectPrincipals = new List<SecurityPrincipal>();
            this.modifyGPOStorePrincipals = new List<SecurityPrincipal>();
            this.securityFilterTargetPrincipals = new List<SecurityPrincipal>();
            this.linkedOUs = linkedOUs;
        }

        // Returns a list of users contained within linked OUs
        public List<User> getLinkedUsers()
        {
            List<User> results = new List<User>();

            foreach (OU ou in linkedOUs)
            {
                results.AddRange(ou.childUsers);
            }

            return results;
        }

        // Returns a list of computers contained within linked OUs
        public List<Computer> getLinkedComputers()
        {
            List<Computer> results = new List<Computer>();

            foreach (OU ou in linkedOUs)
            {
                results.AddRange(ou.childComputers);
            }

            return results;
        }

        // Populates the addModifyGPOObject list with a set of principals that can modify the GPO's AD object
        public void checkGPOObjectPrincipals(NetworkCredential credentials)
        {
            WritePermissionInfo writePermissionsInfo = PermissionsUtils.GetADObjectWritePermissions(this.sd, credentials);

            foreach (string principal in writePermissionsInfo.UsersWithWriteAccess)
            {
                this.addModifyGPOObject(principal);
            }

        }

        // Populates the addModifyGPOStore list with a set of principals that can modify the GPO's backing store
        public void checkGPOStorePrincipals(NetworkCredential credentials)
        {
            WritePermissionInfo writePermissionsInfo = PermissionsUtils.GetBackingStoreWritePermissions(this.filePath, credentials);

            foreach(string principal in writePermissionsInfo.UsersWithWriteAccess)
            {
                this.addModifyGPOStore(principal);
            }
        }

        // Populates the linkedToAtLeastOneOU boolean
        public void checkLinkedtoOUs()
        {
            this.linkedToAtleastOneOU = this.linkedOUs.Count > 0;
        }

        // Populates the securityFilterTargetPrincipals list with principals that the GPO targets
        public void checkSecurityFilterTargetPrincipals()
        {
            Guid APPLY_GROUP_POLICY_GUID = new Guid("edacfd8f-ffb3-11d1-b41d-00a0c968f939"); // Apply-Group-Policy extended right
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (ace is ObjectAce objAce) // Check if it's an ObjectAce
                {
                    if (objAce.ObjectAceType == APPLY_GROUP_POLICY_GUID) // Match Apply Group Policy right
                    {
                        SecurityIdentifier sid = objAce.SecurityIdentifier;
                        string principal = null;
                        try
                        {
                            principal = sid.Translate(typeof(NTAccount)).ToString();
                        }
                        catch
                        {
                            principal = sid.ToString(); // Adds the specified sid value if it cannot be translated to an AD object
                        }
                        this.addSecurityFilterTarget(principal);
                    }
                }
            }
        }

        private void addModifyGPOObject(string principal) {
            this.modifyGPOObjectPrincipals.Add(new SecurityPrincipal(principal));
        }

        private void addModifyGPOStore(string principal) { 
            this.modifyGPOStorePrincipals.Add(new SecurityPrincipal(principal));
        }

        private void addSecurityFilterTarget(string principal)
        {
            this.securityFilterTargetPrincipals.Add(new SecurityPrincipal(principal));
        }
    }
}
