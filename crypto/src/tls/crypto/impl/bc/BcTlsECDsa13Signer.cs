using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for generation of ECDSA signatures in TLS 1.3+ using the BC light-weight API.
    /// </summary>
    public class BcTlsECDsa13Signer
        : BcTlsSigner
    {
        private readonly int m_signatureScheme;

        public BcTlsECDsa13Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, int signatureScheme)
            : base(crypto, privateKey)
        {
            if (!SignatureScheme.IsECDsa(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(m_signatureScheme);
            IDsa dsa = new ECDsaSigner(new HMacDsaKCalculator(m_crypto.CreateDigest(cryptoHashAlgorithm)));

            ISigner signer = new DsaDigestSigner(dsa, new NullDigest());
            signer.Init(true, new ParametersWithRandom(m_privateKey, m_crypto.SecureRandom));
            signer.BlockUpdate(hash, 0, hash.Length);
            try
            {
                return signer.GenerateSignature();
            }
            catch (CryptoException e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }
    }
}
