using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

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
                throw new ArgumentException("'privateKey' type not supported: " + privateKey.GetType().FullName);
            }

            m_crypto = crypto;
            m_certificate = certificate;
            m_privateKey = privateKey;
        }

        public virtual Certificate Certificate => m_certificate;

        public virtual TlsSecret Decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext)
        {
            // TODO Keep only the decryption itself here - move error handling outside 
            return SafeDecryptPreMasterSecret(cryptoParams, (RsaKeyParameters)m_privateKey, ciphertext);
        }

        /*
         * TODO[tls-ops] Probably need to make RSA encryption/decryption into TlsCrypto functions so that users can
         * implement "generic" encryption credentials externally
         */
        protected virtual TlsSecret SafeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams,
            RsaKeyParameters rsaServerPrivateKey, byte[] encryptedPreMasterSecret)
        {
            ProtocolVersion expectedVersion = cryptoParams.RsaPreMasterSecretVersion;

            byte[] M = Org.BouncyCastle.Crypto.Tls.TlsRsaKeyExchange.DecryptPreMasterSecret(encryptedPreMasterSecret,
                rsaServerPrivateKey, expectedVersion.FullVersion, m_crypto.SecureRandom);

            return m_crypto.CreateSecret(M);
        }
    }
}
