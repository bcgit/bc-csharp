using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>ECDH key agreement followed by a key derivation function.</summary>
    // TODO[api] sealed, avoid inheritance
    public class ECDHWithKdfBasicAgreement
        : ECDHBasicAgreement
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly IDerivationFunction m_kdf;
        private byte[] m_ukm;

        /// <summary>Create a new <see cref="ECDHWithKdfBasicAgreement"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="kdf">The kdf.</param>
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
            parameters = ParameterUtilities.GetUkm(parameters, out m_ukm);
            base.Init(parameters);
        }

        /// <inheritdoc/>
        public override BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            BigInteger result = base.CalculateAgreement(pubKey);

            return BasicAgreementWithKdf.CalculateAgreementWithKdf(m_algID, m_kdf, GetFieldSize(), result, m_ukm);
        }
    }
}
