using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    // TODO[api] sealed, avoid inheritance
    public class ECDHWithKdfBasicAgreement
        : ECDHBasicAgreement
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly IDerivationFunction m_kdf;
        private byte[] m_ukm;

        [Obsolete("Use '(AlgorithmIdentifier, ...)' instead")]
        public ECDHWithKdfBasicAgreement(string algorithm, IDerivationFunction kdf)
            : this(DHKdfParameters.WithDefaultParameters(algorithm), kdf)
        {
        }

        public ECDHWithKdfBasicAgreement(AlgorithmIdentifier algID, IDerivationFunction kdf)
        {
            m_algID = algID ?? throw new ArgumentNullException(nameof(algID));
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
        }

        public override void Init(ICipherParameters parameters)
        {
            parameters = ParameterUtilities.IgnoreRandom(parameters);
            parameters = ParameterUtilities.GetUkm(parameters, out m_ukm);
            base.Init(parameters);
        }

        public override BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            BigInteger result = base.CalculateAgreement(pubKey);

            return BasicAgreementWithKdf.CalculateAgreementWithKdf(m_algID, m_kdf, GetFieldSize(), result, m_ukm);
        }
    }
}
