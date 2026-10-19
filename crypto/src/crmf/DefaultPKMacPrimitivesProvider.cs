using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>The default provider of the digests and MACs used for PKMAC calculations.</summary>
    public class DefaultPKMacPrimitivesProvider
        : IPKMacPrimitivesProvider
    {
        /// <summary>Create the digest for the given algorithm using <see cref="DigestUtilities"/>.</summary>
        /// <param name="digestAlg">The digest algorithm.</param>
        public IDigest CreateDigest(AlgorithmIdentifier digestAlg)
        {
            return DigestUtilities.GetDigest(digestAlg.Algorithm);
        }

        /// <summary>Create the MAC for the given algorithm using <see cref="MacUtilities"/>.</summary>
        /// <param name="macAlg">The MAC algorithm.</param>
        public IMac CreateMac(AlgorithmIdentifier macAlg)
        {
            return MacUtilities.GetMac(macAlg.Algorithm);
        }
    }
}
