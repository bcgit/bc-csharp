using System;
using System.Reflection;
using System.Runtime.CompilerServices;

#if PORTABLE
using System.Linq;
#else
using System.Runtime.InteropServices;
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
                version = typeof(AssemblyInfo).Assembly.GetName().Version.ToString();
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

#if NET40
namespace System.Reflection
{
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true, Inherited = false)]
    internal sealed class AssemblyMetadataAttribute : Attribute
    {
        public AssemblyMetadataAttribute(string key, string value)
        {
            Key = key;
            Value = value;
        }

        public string Key { get; }

        public string Value { get; }
    }
}

#endif
