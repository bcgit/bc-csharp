using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants for the name types of the server_name extension of RFC 6066.</summary>
    public abstract class NameType
    {
        /*
         * RFC 3546 3.1.
         */
        public const short host_name = 0;

        /// <summary>Get the name of the given name type.</summary>
        /// <param name="nameType">The name type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short nameType)
        {
            switch (nameType)
            {
            case host_name:
                return "host_name";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given name type, made up of its name and its numeric value.
        /// </summary>
        /// <param name="nameType">The name type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short nameType)
        {
            return GetName(nameType) + "(" + nameType + ")";
        }

        /// <summary>Determine whether the given name type is a recognized value.</summary>
        /// <param name="nameType">The name type.</param>
        /// <returns>true if the value is recognized, false otherwise.</returns>
        public static bool IsRecognized(short nameType)
        {
            return host_name == nameType;
        }

        /// <summary>Determine whether the given name type is a valid value.</summary>
        /// <param name="nameType">The name type.</param>
        /// <returns>true if the value is valid, false otherwise.</returns>
        public static bool IsValid(short nameType)
        {
            return TlsUtilities.IsValidUint8(nameType);
        }
    }
}
