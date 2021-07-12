using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Credentialed class decrypting RSA encrypted secrets sent from a peer for our end of the TLS connection
    /// using the BC light-weight API.</summary>
    public class BcDefaultTlsCredentialedDecryptor
        : TlsCredentialedDecryptor
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly Certificate m_certificate;
        protected readonly AsymmetricKeyParameter m_privateKey;

        public BcDefaultTlsCredentialedDecryptor(BcTlsCrypto crypto, Certificate certificate,
            AsymmetricKeyParameter privateKey)
        {
            if (crypto == null)
                throw new ArgumentNullException("crypto");
            if (certificate == null)
                throw new ArgumentNullException("certificate");
            if (certificate.IsEmpty)
                throw new ArgumentException("cannot be empty", "certificate");
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");
            if (!privateKey.IsPrivate)
                throw new ArgumentException("must be private", "privateKey");

            if (privateKey is RsaKeyParameters)
            {
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: " + Platform.GetTypeName(privateKey));
            }

            this.m_crypto = crypto;
            this.m_certificate = certificate;
            this.m_privateKey = privateKey;
        }

        public virtual Certificate Certificate
        {
            get { return m_certificate; }
        }

        public virtual TlsSecret Decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext)
        {
            // TODO Keep only the decryption itself here - move error handling outside 
            return SafeDecryptPreMasterSecret(cryptoParams, (RsaKeyParameters)m_privateKey, ciphertext);
        }

        /*
         * TODO[tls-ops] Probably need to make RSA encryption/decryption into TlsCrypto functions so
         * that users can implement "generic" encryption credentials externally
         */
        protected virtual TlsSecret SafeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams,
            RsaKeyParameters rsaServerPrivateKey, byte[] encryptedPreMasterSecret)
        {
            SecureRandom secureRandom = m_crypto.SecureRandom;

            /*
             * RFC 5246 7.4.7.1.
             */
            ProtocolVersion expectedVersion = cryptoParams.RsaPreMasterSecretVersion;

            // TODO Provide as configuration option?
            bool versionNumberCheckDisabled = false;

            /*
             * Generate 48 random bytes we can use as a Pre-Master-Secret, if the
             * PKCS1 padding check should fail.
             */
            byte[] fallback = new byte[48];
            secureRandom.NextBytes(fallback);

            byte[] M = Arrays.Clone(fallback);
            try
            {
                Pkcs1Encoding encoding = new Pkcs1Encoding(new RsaBlindedEngine(), fallback);
                encoding.Init(false, new ParametersWithRandom(rsaServerPrivateKey, secureRandom));

                M = encoding.ProcessBlock(encryptedPreMasterSecret, 0, encryptedPreMasterSecret.Length);
            }
            catch (Exception)
            {
                /*
                 * This should never happen since the decryption should never throw an exception
                 * and return a random value instead.
                 *
                 * In any case, a TLS server MUST NOT generate an alert if processing an
                 * RSA-encrypted premaster secret message fails, or the version number is not as
                 * expected. Instead, it MUST continue the handshake with a randomly generated
                 * premaster secret.
                 */
            }

            /*
             * If ClientHello.legacy_version is TLS 1.1 or higher, server implementations MUST check the
             * version number [..].
             */
            if (versionNumberCheckDisabled && !TlsImplUtilities.IsTlsV11(expectedVersion))
            {
                /*
                 * If the version number is TLS 1.0 or earlier, server implementations SHOULD check the
                 * version number, but MAY have a configuration option to disable the check.
                 */
            }
            else
            {
                /*
                 * Compare the version number in the decrypted Pre-Master-Secret with the legacy_version
                 * field from the ClientHello. If they don't match, continue the handshake with the
                 * randomly generated 'fallback' value.
                 *
                 * NOTE: The comparison and replacement must be constant-time.
                 */
                int mask = (expectedVersion.MajorVersion ^ (M[0] & 0xFF))
                         | (expectedVersion.MinorVersion ^ (M[1] & 0xFF));

                // 'mask' will be all 1s if the versions matched, or else all 0s.
                mask = (mask - 1) >> 31;

                for (int i = 0; i < 48; i++)
                {
                    M[i] = (byte)((M[i] & mask) | (fallback[i] & ~mask));
                }
            }

            return m_crypto.CreateSecret(M);
        }
    }
}
