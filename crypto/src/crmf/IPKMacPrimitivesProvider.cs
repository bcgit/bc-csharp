using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Provider of the digests and MACs used for PKMAC calculations.</summary>
    public interface IPKMacPrimitivesProvider
    {
        /// <summary>Create the digest for the given algorithm.</summary>
        /// <param name="digestAlg">The digest algorithm.</param>
        IDigest CreateDigest(AlgorithmIdentifier digestAlg);

        /// <summary>Create the MAC for the given algorithm.</summary>
        /// <param name="macAlg">The MAC algorithm.</param>
        IMac CreateMac(AlgorithmIdentifier macAlg);
    }
}
