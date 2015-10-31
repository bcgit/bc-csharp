using System;
using System.Reflection;
//using System.Security.Permissions;

#if PORTABLE
using System.Linq;
#else
using System.Runtime.InteropServices;
#endif

//
// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
//
[assembly: AssemblyTitle("BouncyCastle.Crypto")]
[assembly: AssemblyDescription("Bouncy Castle Cryptography API")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("The Legion of the Bouncy Castle Inc.")]
[assembly: AssemblyProduct("Bouncy Castle for .NET")]
[assembly: AssemblyCopyright("Copyright (C) 2000-2015")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

//
// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Revision and Build Numbers
// by using the '*' as shown below:

[assembly: AssemblyVersion("1.8.*")]

[assembly: CLSCompliant(true)]
#if !PORTABLE
[assembly: ComVisible(false)]
#endif

// Start with no permissions
//[assembly: PermissionSet(SecurityAction.RequestOptional, Unrestricted=false)]
//...and explicitly add those we need

// see Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding.StrictLengthEnabledProperty
//[assembly: EnvironmentPermission(SecurityAction.RequestOptional, Read="Org.BouncyCastle.Pkcs1.Strict")]

internal class AssemblyInfo
{
    private static string version;
    public static string Version
    {
        get
        {
            if (version == null)
            {
#if PORTABLE
#if NEW_REFLECTION
                var ver = (AssemblyVersionAttribute)typeof(AssemblyInfo).GetTypeInfo().Assembly.GetCustomAttributes(typeof(AssemblyVersionAttribute)).FirstOrDefault();
#else
                var ver = (AssemblyVersionAttribute)typeof(AssemblyInfo).Assembly.GetCustomAttributes(typeof(AssemblyVersionAttribute), false).FirstOrDefault();
#endif
                if (ver != null)
                {
                    version = ver.Version;
                }
#else
                version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
#endif

                // if we're still here, then don't try again
                if (version == null)
                    version = string.Empty;
            }

            return version;
        }
    }
}
