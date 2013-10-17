using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace Org.BouncyCastle.Crypto.Tls
{

    public class DefaultTlsEncryptionCredentials : TlsEncryptionCredentials
    {
        protected TlsContext context;
        private Certificate certificate;
        private AsymmetricKeyParameter privateKey;

        public DefaultTlsEncryptionCredentials(TlsContext context, Certificate certificate,
                                               AsymmetricKeyParameter privateKey)
        {
            if (certificate == null)
            {
                throw new ArgumentException("'certificate' cannot be null");
            }
            if (certificate.IsEmpty)
            {
                throw new ArgumentException("'certificate' cannot be empty");
            }
            if (privateKey == null)
            {
                throw new ArgumentException("'privateKey' cannot be null");
            }
            if (!privateKey.IsPrivate)
            {
                throw new ArgumentException("'privateKey' must be private");
            }

            if (privateKey is RsaKeyParameters)
            {
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: "
                    + privateKey.GetType().Name);
            }

            this.context = context;
            this.certificate = certificate;
            this.privateKey = privateKey;
        }

        public Certificate Certificate
        {
            get
            {
                return certificate;
            }
        }

        public byte[] DecryptPreMasterSecret(byte[] encryptedPreMasterSecret)
        {
            Pkcs1Encoding encoding = new Pkcs1Encoding(new RsaBlindedEngine());
            encoding.Init(false, new ParametersWithRandom(this.privateKey, context.SecureRandom));

            try
            {
                return encoding.ProcessBlock(encryptedPreMasterSecret, 0,
                    encryptedPreMasterSecret.Length);
            }
            catch (InvalidCipherTextException e)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
            }
        }
    }
}