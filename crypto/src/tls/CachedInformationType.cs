using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants for the cached information types of RFC 7924.</summary>
    public abstract class CachedInformationType
    {
        /// <summary>The <c>cert</c> constant, with the value <c>1</c>.</summary>
        public const short cert = 1;
        /// <summary>The <c>cert_req</c> constant, with the value <c>2</c>.</summary>
        public const short cert_req = 2;

        /// <summary>Get the name of the given cached information type.</summary>
        /// <param name="cachedInformationType">The cached information type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short cachedInformationType)
        {
            switch (cachedInformationType)
            {
            case cert:
                return "cert";
            case cert_req:
                return "cert_req";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given cached information type, made up of its name and its numeric
        /// value.
        /// </summary>
        /// <param name="cachedInformationType">The cached information type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short cachedInformationType)
        {
            return GetName(cachedInformationType) + "(" + cachedInformationType + ")";
        }
    }
}
