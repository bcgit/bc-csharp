using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement
{
    // TODO[api] sealed, avoid inheritance
    public class ECMqvWithKdfBasicAgreement
        : ECMqvBasicAgreement
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly IDerivationFunction m_kdf;

        [Obsolete("Use '(AlgorithmIdentifier, ...)' instead")]
        public ECMqvWithKdfBasicAgreement(string algorithm, IDerivationFunction kdf)
            : this(DHKdfParameters.WithDefaultParameters(algorithm), kdf)
        {
        }

        public ECMqvWithKdfBasicAgreement(AlgorithmIdentifier algID, IDerivationFunction kdf)
        {
            m_algID = algID ?? throw new ArgumentNullException(nameof(algID));
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
        }

        public override BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            BigInteger result = base.CalculateAgreement(pubKey);

            return BasicAgreementWithKdf.CalculateAgreementWithKdf(m_algID, m_kdf, GetFieldSize(), result);
        }
    }
}
