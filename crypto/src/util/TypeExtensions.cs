using System;
using System.Reflection;

#if NEW_REFLECTION

namespace Org.BouncyCastle
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