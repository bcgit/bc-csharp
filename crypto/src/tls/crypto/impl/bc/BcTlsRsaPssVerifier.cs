using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Operator supporting the verification of RSASSA-PSS signatures using the BC light-weight API.</summary>
    public class BcTlsRsaPssVerifier
        : BcTlsVerifier
    {
        private readonly int m_signatureScheme;

        public BcTlsRsaPssVerifier(BcTlsCrypto crypto, RsaKeyParameters publicKey, int signatureScheme)
            : base(crypto, publicKey)
        {
            if (!SignatureScheme.IsRsaPss(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(m_signatureScheme);
            IDigest digest = m_crypto.CreateDigest(cryptoHashAlgorithm);

            PssSigner verifier = PssSigner.CreateRawSigner(new RsaEngine(), digest, digest, digest.GetDigestSize(),
                PssSigner.TrailerImplicit);
            verifier.Init(false, m_publicKey);
            verifier.BlockUpdate(hash, 0, hash.Length);
            return verifier.VerifySignature(digitallySigned.Signature);
        }
    }
}
