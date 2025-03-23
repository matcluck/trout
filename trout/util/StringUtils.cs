using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using trout.models;

namespace trout.util
{
    class StringUtils
    {
        public static string GetLDAPFormattedDomainName(string domain)
        {
            // Split the domain name into parts and convert it into the required LDAP format
            string[] domainParts = domain.Split('.');
            string ldapDomain = string.Join(",", domainParts.Select(part => $"DC={part}"));

            return ldapDomain;
     
            
        }

        public static string GetLimitedListWithEllipsis<T>(List<T> items)
        {
            const int limit = 10;
            var limitedItems = items.Take(limit).ToList();
            var result = string.Join(",", limitedItems.Select(item => item.ToString()));

            if (items.Count > limit)
            {
                result += ",...";  // Add ellipsis if there are more than 20
            }

            return result;
        }
    }
}
