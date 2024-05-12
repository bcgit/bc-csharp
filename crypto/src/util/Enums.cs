using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Utilities
{
    internal static class Enums
    {
        internal static TEnum[] GetEnumValues<TEnum>()
            where TEnum : struct, Enum
        {
#if NET5_0_OR_GREATER
            return Enum.GetValues<TEnum>();
#else
            return (TEnum[])Enum.GetValues(typeof(TEnum));
#endif
        }

        internal static TEnum GetArbitraryValue<TEnum>()
            where TEnum : struct, Enum
        {
            TEnum[] values = GetEnumValues<TEnum>();
            int pos = (int)(DateTimeUtilities.CurrentUnixMs() & int.MaxValue) % values.Length;
            return values[pos];
        }

        internal static bool TryGetEnumValue<TEnum>(string s, out TEnum result)
            where TEnum : struct, Enum
        {
            // We only want to parse single named constants
            if (s.Length > 0 && char.IsLetter(s[0]) && s.IndexOf(',') < 0)
            {
                s = s.Replace('-', '_');
                s = s.Replace('/', '_');

                return Enum.TryParse<TEnum>(s, out result);
            }

            result = default(TEnum);
            return false;
        }
    }
}
