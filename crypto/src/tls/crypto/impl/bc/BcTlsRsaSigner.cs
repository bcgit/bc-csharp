using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Operator supporting the generation of RSASSA-PKCS1-v1_5 signatures using the BC light-weight API.
    /// </summary>
    public class BcTlsRsaSigner
        : BcTlsSigner
    {
        [Obsolete("Use constructor without 'publicKey' parameter instead")]
        public BcTlsRsaSigner(BcTlsCrypto crypto, RsaKeyParameters privateKey, RsaKeyParameters publicKey)
            : this(crypto, privateKey)
        {
        }

        public BcTlsRsaSigner(BcTlsCrypto crypto, RsaKeyParameters privateKey)
            : base(crypto, privateKey)
        {
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            IDigest nullDigest = new NullDigest();

            ISigner signer;
            if (algorithm != null)
            {
                if (algorithm.Signature != SignatureAlgorithm.rsa)
                    throw new InvalidOperationException("Invalid algorithm: " + algorithm);

                /*
                 * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
                 * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
                 */
                signer = new RsaDigestSigner(nullDigest, TlsUtilities.GetOidForHashAlgorithm(algorithm.Hash));
            }
            else
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
                 * that did not include a DigestInfo encoding.
                 */
                signer = new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), nullDigest);
            }
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
