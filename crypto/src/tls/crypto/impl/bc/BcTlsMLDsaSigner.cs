using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsMLDsaSigner
        : BcTlsSigner
    {
        public static BcTlsMLDsaSigner Create(BcTlsCrypto crypto, MLDsaPrivateKeyParameters privateKey, int signatureScheme)
        {
            if (signatureScheme != PqcUtilities.GetMLDsaSignatureScheme(privateKey.Parameters))
                return null;

            return new BcTlsMLDsaSigner(crypto, privateKey, signatureScheme);
        }

        private readonly int m_signatureScheme;

        private BcTlsMLDsaSigner(BcTlsCrypto crypto, MLDsaPrivateKeyParameters privateKey, int signatureScheme)
            : base(crypto, privateKey)
        {
            m_signatureScheme = signatureScheme;
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            var mlDsaAlgOid = PqcUtilities.GetMLDsaObjectidentifier(m_signatureScheme);

            var signer = SignerUtilities.InitSigner(mlDsaAlgOid, forSigning: true, m_privateKey, m_crypto.SecureRandom);

            return new BcTlsStreamSigner(signer);
        }
    }
}
