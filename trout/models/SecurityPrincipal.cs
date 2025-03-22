using System;
using System.Text.RegularExpressions;
using trout.util;

namespace trout.models
{
    public class SecurityPrincipal
    {
        public string name { get; private set; }
        public bool IsDomainPrincipal { get; private set; }

        public SecurityPrincipal(string principalName)
        {
            name = principalName;
            IsDomainPrincipal = IsDomainPrincipalName(principalName);
        }

        private bool IsDomainPrincipalName(string principalName)
        {
            // Regex to check if the name is a SID (Domain Principal)
            string sidPattern = @"^S-\d(-\d+)+$";

            return Regex.IsMatch(principalName, sidPattern);
        }

        public override string ToString()
        {
            return $"{name} ({(IsDomainPrincipal ? "Domain Principal" : "Common Principal")})";
        }

        public string ToHumanString(string domain)
        {
            if (this.IsDomainPrincipal)
            {
                return LDAPUtils.ResolveSidToNameUsingLdap(this.name, domain);
            }
            return this.name;
        }
    }
}



