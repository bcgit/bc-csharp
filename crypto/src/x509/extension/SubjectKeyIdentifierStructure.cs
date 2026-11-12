using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.X509.Extension
{
    /// <summary>A high level subject key identifier.</summary>
    [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
    public class SubjectKeyIdentifierStructure
        : SubjectKeyIdentifier
    {
        /// <summary>Create from the value of a subject key identifier extension.</summary>
        /// <param name="encodedValue">The extension value.</param>
        public SubjectKeyIdentifierStructure(Asn1OctetString encodedValue)
            : base(Asn1OctetString.GetInstance(encodedValue.GetOctets()))
        {
        }

        /// <summary>Create a subject key identifier from the hash of the given public key.</summary>
        /// <param name="pubKey">The public key to generate the hash from.</param>
        public SubjectKeyIdentifierStructure(AsymmetricKeyParameter pubKey)
            : base(keyID: X509ExtensionUtilities.CalculateKeyIdentifier(pubKey))
        {
        }
    }
}
