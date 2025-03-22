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

        public List<User> getLinkedUsers()
        {
            List<User> results = new List<User>();

            foreach (OU ou in linkedOUs)
            {
                results.AddRange(ou.childUsers);
            }

            return results;
        }

        public List<Computer> getLinkedComputers()
        {
            List<Computer> results = new List<Computer>();

            foreach (OU ou in linkedOUs)
            {
                results.AddRange(ou.childComputers);
            }

            return results;
        }

        public void checkGPOLinks(NetworkCredential credentials)
        {

        }


        public void checkGPOObjectPrincipals(NetworkCredential credentials)
        {
            WritePermissionInfo writePermissionsInfo = PermissionsUtils.GetADObjectWritePermissions(this.sd, credentials);

            foreach (string principal in writePermissionsInfo.UsersWithWriteAccess)
            {
                this.addModifyGPOObject(principal);
            }

            if (writePermissionsInfo.SecurityContextHasWrite)
            {
                this.adObjectModifiable = true;
            }
        }

        public void checkGPOStorePrincipals(NetworkCredential credentials)
        {
            WritePermissionInfo writePermissionsInfo = PermissionsUtils.GetBackingStoreWritePermissions(this.filePath, credentials);

            foreach(string principal in writePermissionsInfo.UsersWithWriteAccess)
            {
                this.addModifyGPOStore(principal);
            }

            if (writePermissionsInfo.SecurityContextHasWrite)
            {
                this.backingStoreModifiable = true;
            }
        }

        public void checkLinkedtoOUs()
        {
            this.linkedToAtleastOneOU = this.linkedOUs.Count > 0;
        }

        public void checkSecurityFilterTargetPrincipals()
        {
            Guid APPLY_GROUP_POLICY_GUID = new Guid("edacfd8f-ffb3-11d1-b41d-00a0c968f939");
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
                            principal = sid.ToString();
                        }
                        this.securityFilterTargetPrincipals.Add(new SecurityPrincipal(principal));
                    }
                }
            }
        }

        public void addModifyGPOObject(string principal) {
            this.modifyGPOObjectPrincipals.Add(new SecurityPrincipal(principal));
        }

        public void addModifyGPOStore(string principal) { 
            this.modifyGPOStorePrincipals.Add(new SecurityPrincipal(principal));
        }

        public void addSecurityFilterTarget(string principal)
        {
            this.securityFilterTargetPrincipals.Add(new SecurityPrincipal(principal));
        }
    }
}
