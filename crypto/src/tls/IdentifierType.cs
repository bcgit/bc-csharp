using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 6066</summary>
    public abstract class IdentifierType
    {
        /// <summary>The <c>pre_agreed</c> constant, with the value <c>0</c>.</summary>
        public const short pre_agreed = 0;
        /// <summary>The <c>key_sha1_hash</c> constant, with the value <c>1</c>.</summary>
        public const short key_sha1_hash = 1;
        /// <summary>The <c>x509_name</c> constant, with the value <c>2</c>.</summary>
        public const short x509_name = 2;
        /// <summary>The <c>cert_sha1_hash</c> constant, with the value <c>3</c>.</summary>
        public const short cert_sha1_hash = 3;

        /// <summary>Get the name of the given identifier type.</summary>
        /// <param name="identifierType">The identifier type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short identifierType)
        {
            switch (identifierType)
            {
            case pre_agreed:
                return "pre_agreed";
            case key_sha1_hash:
                return "key_sha1_hash";
            case x509_name:
                return "x509_name";
            case cert_sha1_hash:
                return "cert_sha1_hash";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given identifier type, made up of its name and its numeric value.
        /// </summary>
        /// <param name="identifierType">The identifier type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short identifierType)
        {
            return GetName(identifierType) + "(" + identifierType + ")";
        }
    }
}
