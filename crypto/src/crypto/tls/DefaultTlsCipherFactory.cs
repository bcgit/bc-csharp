using System;
using System.IO;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class DefaultTlsCipherFactory
        : AbstractTlsCipherFactory
    {
        public override TlsCipher CreateCipher(TlsContext context,
            EncryptionAlgorithm encryptionAlgorithm, MACAlgorithm digestAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
                case EncryptionAlgorithm.cls_3DES_EDE_CBC:
                    return CreateDESedeCipher(context, digestAlgorithm);
                case EncryptionAlgorithm.AES_128_CBC:
                    return CreateAESCipher(context, 16, digestAlgorithm);
                case EncryptionAlgorithm.AES_128_CCM:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_CCM(context, 16, 16);
                case EncryptionAlgorithm.AES_128_CCM_8:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_CCM(context, 16, 8);
                case EncryptionAlgorithm.AES_256_CCM:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_CCM(context, 32, 16);
                case EncryptionAlgorithm.AES_256_CCM_8:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_CCM(context, 32, 8);
                case EncryptionAlgorithm.AES_128_GCM:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_GCM(context, 16, 16);
                case EncryptionAlgorithm.AES_256_CBC:
                    return CreateAESCipher(context, 32, digestAlgorithm);
                case EncryptionAlgorithm.AES_256_GCM:
                    // NOTE: Ignores macAlgorithm
                    return CreateCipher_AES_GCM(context, 32, 16);
                case EncryptionAlgorithm.CAMELLIA_128_CBC:
                    return CreateCamelliaCipher(context, 16, digestAlgorithm);
                case EncryptionAlgorithm.CAMELLIA_256_CBC:
                    return CreateCamelliaCipher(context, 32, digestAlgorithm);
                case EncryptionAlgorithm.ESTREAM_SALSA20:
                    return CreateSalsa20Cipher(context, 12, 32, digestAlgorithm);
                case EncryptionAlgorithm.NULL:
                    return CreateNullCipher(context, digestAlgorithm);
                case EncryptionAlgorithm.RC4_128:
                    return CreateRC4Cipher(context, 16, digestAlgorithm);
                case EncryptionAlgorithm.SALSA20:
                    return CreateSalsa20Cipher(context, 20, 32, digestAlgorithm);
                case EncryptionAlgorithm.SEED_CBC:
                    return CreateSEEDCipher(context, digestAlgorithm);
                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected TlsBlockCipher CreateAESCipher(TlsContext context, int cipherKeySize, MACAlgorithm macAlgorithm)
        {
            return new TlsBlockCipher(context, CreateAESBlockCipher(), CreateAESBlockCipher(),
                CreateHMACDigest(macAlgorithm), CreateHMACDigest(macAlgorithm), cipherKeySize);
        }

        protected TlsAEADCipher CreateCipher_AES_CCM(TlsContext context, int cipherKeySize, int macSize)
        {
            return new TlsAEADCipher(context, CreateAEADBlockCipher_AES_CCM(),
                CreateAEADBlockCipher_AES_CCM(), cipherKeySize, macSize);
        }

        protected TlsAEADCipher CreateCipher_AES_GCM(TlsContext context, int cipherKeySize, int macSize)
        {
            return new TlsAEADCipher(context, CreateAEADBlockCipher_AES_GCM(),
                CreateAEADBlockCipher_AES_GCM(), cipherKeySize, macSize);
        }

        protected TlsBlockCipher CreateCamelliaCipher(TlsContext context, int cipherKeySize,
                                                      MACAlgorithm macAlgorithm)
        {
            return new TlsBlockCipher(context, CreateCamelliaBlockCipher(),
                CreateCamelliaBlockCipher(), CreateHMACDigest(macAlgorithm),
                CreateHMACDigest(macAlgorithm), cipherKeySize);
        }

        protected TlsNullCipher CreateNullCipher(TlsContext context, MACAlgorithm macAlgorithm)
        {
            return new TlsNullCipher(context, CreateHMACDigest(macAlgorithm),
                CreateHMACDigest(macAlgorithm));
        }

        protected TlsStreamCipher CreateRC4Cipher(TlsContext context, int cipherKeySize,
                                                  MACAlgorithm macAlgorithm)
        {
            return new TlsStreamCipher(context, CreateRC4StreamCipher(), CreateRC4StreamCipher(),
                CreateHMACDigest(macAlgorithm), CreateHMACDigest(macAlgorithm), cipherKeySize);
        }

        protected TlsStreamCipher CreateSalsa20Cipher(TlsContext context, int rounds, int cipherKeySize, MACAlgorithm macAlgorithm)
        {
            /*
             * TODO To be able to support UMAC96, we need to give the TlsStreamCipher a Mac instead of
             * assuming HMAC and passing a digest.
             */
            return new TlsStreamCipher(context, CreateSalsa20StreamCipher(rounds), CreateSalsa20StreamCipher(rounds),
                CreateHMACDigest(macAlgorithm), CreateHMACDigest(macAlgorithm), cipherKeySize);
        }

        protected TlsBlockCipher CreateDESedeCipher(TlsContext context, MACAlgorithm macAlgorithm)
        {
            return new TlsBlockCipher(context, CreateDESedeBlockCipher(), CreateDESedeBlockCipher(),
                CreateHMACDigest(macAlgorithm), CreateHMACDigest(macAlgorithm), 24);
        }

        protected TlsBlockCipher CreateSEEDCipher(TlsContext context, MACAlgorithm macAlgorithm)
        {
            return new TlsBlockCipher(context, CreateSEEDBlockCipher(), CreateSEEDBlockCipher(),
                CreateHMACDigest(macAlgorithm), CreateHMACDigest(macAlgorithm), 16);
        }

        protected IStreamCipher CreateRC4StreamCipher()
        {
            return new RC4Engine();
        }

        protected IBlockCipher CreateAESBlockCipher()
        {
            return new CbcBlockCipher(new AesFastEngine());
        }

        protected IAeadBlockCipher CreateAEADBlockCipher_AES_CCM()
        {
            return new CcmBlockCipher(new AesFastEngine());
        }

        protected IAeadBlockCipher CreateAEADBlockCipher_AES_GCM()
        {
            // TODO Consider allowing custom configuration of multiplier
            return new GcmBlockCipher(new AesFastEngine());
        }

        protected IBlockCipher CreateCamelliaBlockCipher()
        {
            return new CbcBlockCipher(new CamelliaEngine());
        }

        protected IBlockCipher CreateDESedeBlockCipher()
        {
            return new CbcBlockCipher(new DesEdeEngine());
        }

        protected IStreamCipher CreateSalsa20StreamCipher(int rounds)
        {
            return new Salsa20Engine(rounds);
        }

        protected IBlockCipher CreateSEEDBlockCipher()
        {
            return new CbcBlockCipher(new SeedEngine());
        }

        protected IDigest CreateHMACDigest(MACAlgorithm macAlgorithm)
        {
            switch (macAlgorithm)
            {
                case MACAlgorithm.Null:
                    return null;
                case MACAlgorithm.hmac_md5:
                    return new MD5Digest();
                case MACAlgorithm.hmac_sha1:
                    return new Sha1Digest();
                case MACAlgorithm.hmac_sha256:
                    return new Sha256Digest();
                case MACAlgorithm.hmac_sha384:
                    return new Sha384Digest();
                case MACAlgorithm.hmac_sha512:
                    return new Sha512Digest();
                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}
