using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace trout.util
{
    public class Impersonation
    {
        // P/Invoke declarations to log on a user and impersonate
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, ref int ReturnLength);

        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9; // The new logon type for cross-domain (netonly) authentication.


        // Function to impersonate a user using NetworkCredential
        public static WindowsImpersonationContext ImpersonateUser(NetworkCredential credentials)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                // LogonUser returns a token that we can use to impersonate the user
                bool loggedIn = LogonUser(credentials.UserName, credentials.Domain, credentials.Password,
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref tokenHandle);


                if (!loggedIn)
                    throw new UnauthorizedAccessException("Failed to log in with provided credentials.");

                // Impersonate the user
                WindowsIdentity identity = new WindowsIdentity(tokenHandle);
                return identity.Impersonate();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error impersonating user: {ex.Message}");
                throw;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                    CloseHandle(tokenHandle);
            }
        }
    }
}
