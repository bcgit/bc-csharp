using System;

#if PORTABLE
using System.Collections;
using System.Reflection;
#endif

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Utilities
{
    internal abstract class Enums
    {
        internal static Enum GetEnumValue(System.Type enumType, string s)
        {
            if (!IsEnumType(enumType))
                throw new ArgumentException("Not an enumeration type", "enumType");

            // We only want to parse single named constants
            if (s.Length > 0 && char.IsLetter(s[0]) && s.IndexOf(',') < 0)
            {
                s = s.Replace('-', '_');
                s = s.Replace('/', '_');

                return (Enum)Enum.Parse(enumType, s, false);
            }

            throw new ArgumentException();
        }

        internal static Array GetEnumValues(System.Type enumType)
        {
            if (!IsEnumType(enumType))
                throw new ArgumentException("Not an enumeration type", "enumType");

            return Enum.GetValues(enumType);
        }

        internal static Enum GetArbitraryValue(System.Type enumType)
        {
            Array values = GetEnumValues(enumType);
            int pos = (int)(DateTimeUtilities.CurrentUnixMs() & int.MaxValue) % values.Length;
            return (Enum)values.GetValue(pos);
        }

        internal static bool IsEnumType(System.Type t)
        {
#if NEW_REFLECTION
            return t.GetTypeInfo().IsEnum;
#else
            return t.IsEnum;
#endif
        }
    }
}
