using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The KeyDerivationFunc algorithm identifier of PKCS#5 v2.1.</summary>
    // TODO[api] This is not supposed to be a separate type; remove and use AlgorithmIdentifier
    public class KeyDerivationFunc
        : AlgorithmIdentifier
    {
        internal KeyDerivationFunc(Asn1Sequence seq)
            : base(seq)
        {
        }

        /// <summary>Create a new <see cref="KeyDerivationFunc"/>.</summary>
        /// <param name="id">The id.</param>
        /// <param name="parameters">The parameters.</param>
        public KeyDerivationFunc(
            DerObjectIdentifier id,
            Asn1Encodable parameters)
            : base(id, parameters)
        {
        }
    }
}
