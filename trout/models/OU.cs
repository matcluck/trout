using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using trout.util;

namespace trout.models
{
    public class OU
    {
        public string distinguishedName { get; set; }
        string domain;
        public List<User> childUsers { get; set; }
        public List<Computer> childComputers { get; set; }
        
        public OU(string distinguishedName, string domain)
        {
            this.distinguishedName = distinguishedName;
            this.domain = domain;

            // instantiate empty lists
            this.childUsers = new List<User>();
            this.childComputers = new List<Computer>();
            
            // populate lists
            this.getOUChildren();
        }

        private void getOUChildren()
        {
            List<ADObject> results = LDAPUtils.getOUChildren(this.distinguishedName, domain);

            foreach (ADObject obj in results)
            {
                if (obj is Computer computer)
                {
                    childComputers.Add(computer);
                }
                else if (obj is User user)
                {
                    childUsers.Add(user);
                }
            }
        }
    }
}
