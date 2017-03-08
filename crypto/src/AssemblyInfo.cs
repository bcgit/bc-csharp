using System;
using System.Reflection;
using System.Runtime.CompilerServices;
//using System.Security.Permissions;

#if PORTABLE
using System.Linq;
#else
using System.Runtime.InteropServices;
#endif

[assembly: CLSCompliant(true)]
#if !PORTABLE
[assembly: ComVisible(false)]
#endif

[assembly: InternalsVisibleTo("crypto.test, PublicKey=002400000480000094000000060200000024000052534131000400000100010083A6A1D0D41B8A0FD3061C8DD2BA14DA98F9BF53576AD386A4D021ABD235EE41BC5416683314816908765FAC4951301E159153CF02BF1B31BEC8A2CE6C0110C30CC7BEF54E514D530B703D37629078AB3ECCE1AFA5ED3F9D63F3B50398188A811ADA59827B9E1A4EEEB87D05E4AFE45BEFD69BF2CDFD37F38334B748C8CB7FBC")]

// Start with no permissions
//[assembly: PermissionSet(SecurityAction.RequestOptional, Unrestricted=false)]
//...and explicitly add those we need

// see Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding.StrictLengthEnabledProperty
//[assembly: EnvironmentPermission(SecurityAction.RequestOptional, Read="Org.BouncyCastle.Pkcs1.Strict")]

internal class AssemblyInfo
{
    private static string version = null;

    public static string Version
    {
        get
        {
            if (version == null)
            {
#if PORTABLE
#if NEW_REFLECTION
                var a = typeof(AssemblyInfo).GetTypeInfo().Assembly;
                var c = a.GetCustomAttributes(typeof(AssemblyVersionAttribute));
#else
                var a = typeof(AssemblyInfo).Assembly;
                var c = a.GetCustomAttributes(typeof(AssemblyVersionAttribute), false);
#endif
                var v = (AssemblyVersionAttribute)c.FirstOrDefault();
                if (v != null)
                {
                    version = v.Version;
                }
#else
                version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
#endif

                // if we're still here, then don't try again
                if (version == null)
                {
                    version = string.Empty;
                }
            }

            return version;
        }
    }
}
