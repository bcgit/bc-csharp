using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for verification of ECDSA signatures in TLS 1.3+ using the BC light-weight API.
    /// </summary>
    public class BcTlsECDsa13Verifier
        : BcTlsVerifier
    {
        private readonly int m_signatureScheme;

        public BcTlsECDsa13Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey, int signatureScheme)
            : base(crypto, publicKey)
        {
            if (!SignatureScheme.IsECDsa(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            IDsa dsa = new ECDsaSigner();

            ISigner signer = new DsaDigestSigner(dsa, new NullDigest());
            signer.Init(false, m_publicKey);
            signer.BlockUpdate(hash, 0, hash.Length);
            return signer.VerifySignature(digitallySigned.Signature);
        }
    }
}
