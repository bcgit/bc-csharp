using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsSM2Signer
        : BcTlsSigner
    {
        private readonly byte[] m_identifier;

        public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, byte[] identifier)
            : base(crypto, privateKey)
        {
            m_identifier = Arrays.Clone(identifier);
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.sm2sig_sm3)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            ParametersWithRandom parametersWithRandom = new ParametersWithRandom(m_privateKey, m_crypto.SecureRandom);
            ParametersWithID parametersWithID = new ParametersWithID(parametersWithRandom, m_identifier);

            SM2Signer signer = new SM2Signer();
            signer.Init(true, parametersWithID);

            return new BcTlsStreamSigner(signer);
        }
    }
}
