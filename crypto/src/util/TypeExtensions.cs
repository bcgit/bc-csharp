#if NEW_REFLECTION

using System;
using System.Reflection;

namespace Org.BouncyCastle.Utilities
{
    internal static class TypeExtensions
    {
        public static bool IsInstanceOfType(this Type type, object instance)
        {
            return instance != null && type.GetTypeInfo().IsAssignableFrom(instance.GetType().GetTypeInfo());
        }
    }
}

#endif
