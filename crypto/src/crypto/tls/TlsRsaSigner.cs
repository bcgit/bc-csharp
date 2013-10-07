using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class TlsRsaSigner : AbstractTlsSigner
    {
        public override byte[] GenerateRawSignature(
            AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
        {
            IAsymmetricBlockCipher engine = CreateRSAImpl();
            engine.Init(true, new ParametersWithRandom(privateKey, this.context.SecureRandom));
            return engine.ProcessBlock(md5AndSha1, 0, md5AndSha1.Length);
        }

        public override bool VerifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey,
            byte[] md5AndSha1)
        {
            IAsymmetricBlockCipher engine = CreateRSAImpl();
            engine.Init(false, publicKey);
            byte[] signed = engine.ProcessBlock(sigBytes, 0, sigBytes.Length);
            return Arrays.ConstantTimeAreEqual(signed, md5AndSha1);
        }

        public override ISigner CreateSigner(AsymmetricKeyParameter privateKey)
        {
            return MakeSigner(new CombinedHash(), true,
            new ParametersWithRandom(privateKey, this.context.SecureRandom));
        }

        public override ISigner CreateVerifyer(AsymmetricKeyParameter publicKey)
        {
            return MakeSigner(new CombinedHash(), false, publicKey);
        }

        public override bool IsValidPublicKey(AsymmetricKeyParameter publicKey)
        {
            return publicKey is RsaKeyParameters && !publicKey.IsPrivate;
        }

        protected ISigner MakeSigner(IDigest d, bool forSigning, ICipherParameters cp)
        {
            ISigner s;
            if (TlsUtilities.IsTLSv12(context))
            {
                /*
                 * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
                 * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
                 */
                s = new RsaDigestSigner(d);
            }
            else
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
                 * that did not include a DigestInfo encoding.
                 */
                s = new GenericSigner(CreateRSAImpl(), d);
            }
            s.Init(forSigning, cp);
            return s;
        }

        protected IAsymmetricBlockCipher CreateRSAImpl()
        {
            /*
             * RFC 5264 7.4.7.1. Implementation note: It is now known that remote timing-based attacks
             * on TLS are possible, at least when the client and server are on the same LAN.
             * Accordingly, implementations that use static RSA keys MUST use RSA blinding or some other
             * anti-timing technique, as described in [TIMING].
             */
            return new Pkcs1Encoding(new RsaBlindedEngine());
        }
    }
}
