using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Implementation of the RFC 3546 3.3. CertChainType.</summary>
    public abstract class CertChainType
    {
        /// <summary>The <c>individual_certs</c> constant, with the value <c>0</c>.</summary>
        public const short individual_certs = 0;
        /// <summary>The <c>pkipath</c> constant, with the value <c>1</c>.</summary>
        public const short pkipath = 1;

        /// <summary>Get the name of the given cert chain type.</summary>
        /// <param name="certChainType">The cert chain type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short certChainType)
        {
            switch (certChainType)
            {
            case individual_certs:
                return "individual_certs";
            case pkipath:
                return "pkipath";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given cert chain type, made up of its name and its numeric value.
        /// </summary>
        /// <param name="certChainType">The cert chain type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short certChainType)
        {
            return GetName(certChainType) + "(" + certChainType + ")";
        }

        /// <summary>Determine whether the given cert chain type is a valid value.</summary>
        /// <param name="certChainType">The cert chain type.</param>
        /// <returns>true if the value is valid, false otherwise.</returns>
        public static bool IsValid(short certChainType)
        {
            return certChainType >= individual_certs && certChainType <= pkipath;
        }
    }
}
