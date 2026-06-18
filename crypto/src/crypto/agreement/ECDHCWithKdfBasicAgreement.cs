using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement
{
    // TODO[api] Rename to ECDhcWithKdfBasicAgreement, avoid inheritance
    public sealed class ECDHCWithKdfBasicAgreement
        : ECDHCBasicAgreement
    {
        private readonly string m_algorithm;
        private readonly IDerivationFunction m_kdf;

        public ECDHCWithKdfBasicAgreement(string algorithm, IDerivationFunction kdf)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
        }

        public override BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            BigInteger result = base.CalculateAgreement(pubKey);

            return BasicAgreementWithKdf.CalculateAgreementWithKdf(m_algorithm, m_kdf, GetFieldSize(), result);
        }
    }
}
