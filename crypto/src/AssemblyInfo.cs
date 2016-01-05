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

[assembly: AssemblyVersion("1.8.1.0")]
[assembly: AssemblyFileVersion("1.8.15362.1")]
[assembly: AssemblyInformationalVersion("1.8.1")]

//
// In order to sign your assembly you must specify a key to use. Refer to the
// Microsoft .NET Framework documentation for more information on assembly signing.
//
// Use the attributes below to control which key is used for signing.
//
// Notes:
//   (*) If no key is specified, the assembly is not signed.
//   (*) KeyName refers to a key that has been installed in the Crypto Service
//       Provider (CSP) on your machine. KeyFile refers to a file which contains
//       a key.
//   (*) If the KeyFile and the KeyName values are both specified, the
//       following processing occurs:
//       (1) If the KeyName can be found in the CSP, that key is used.
//       (2) If the KeyName does not exist and the KeyFile does exist, the key
//           in the KeyFile is installed into the CSP and used.
//   (*) In order to create a KeyFile, you can use the sn.exe (Strong Name) utility.
//       When specifying the KeyFile, the location of the KeyFile should be
//       relative to the project output directory which is
//       %Project Directory%\obj\<configuration>. For example, if your KeyFile is
//       located in the project directory, you would specify the AssemblyKeyFile
//       attribute as [assembly: AssemblyKeyFile("..\\..\\mykey.snk")]
//   (*) Delay Signing is an advanced option - see the Microsoft .NET Framework
//       documentation for more information on this.
//
[assembly: AssemblyDelaySign(false)]
#if STRONG_NAME
[assembly: AssemblyKeyFile(@"../BouncyCastle.snk")]
#endif

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
