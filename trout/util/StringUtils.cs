using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace trout.util
{
    class StringUtils
    {
        public static string GetLDAPFormattedDomainName(string domain)
        {
            // Get the current domain using Active Directory

            // Split the domain name into parts and convert it into the required LDAP format
            string[] domainParts = domain.Split('.');
            string ldapDomain = string.Join(",", domainParts.Select(part => $"DC={part}"));

            return ldapDomain;
     
            
        }
    }
}
