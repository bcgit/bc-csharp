using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class DefaultTlsSignerCredentials
        : TlsSignerCredentials
    {
        protected TlsContext context;
        protected Certificate certificate;
        protected AsymmetricKeyParameter privateKey;

        protected TlsSigner signer;

        public DefaultTlsSignerCredentials(TlsContext context,
            Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("clientCertificate");
            }
            if (certificate.IsEmpty)
            {
                throw new ArgumentException("cannot be empty", "clientCertificate");
            }
            if (privateKey == null)
            {
                throw new ArgumentNullException("clientPrivateKey");
            }
            if (!privateKey.IsPrivate)
            {
                throw new ArgumentException("must be private", "clientPrivateKey");
            }

            if (privateKey is RsaKeyParameters)
            {
                signer = new TlsRsaSigner();
            }
            else if (privateKey is DsaPrivateKeyParameters)
            {
                signer = new TlsDssSigner();
            }
            else if (privateKey is ECPrivateKeyParameters)
            {
                signer = new TlsECDsaSigner();
            }
            else
            {
                throw new ArgumentException("type not supported: "
                    + privateKey.GetType().FullName, "clientPrivateKey");
            }

            this.signer.Init(context);

            this.context = context;
            this.certificate = certificate;
            this.privateKey = privateKey;
        }

        public virtual Certificate Certificate
        {
            get
            {
                return certificate;
            }
        }

        public virtual byte[] GenerateCertificateSignature(byte[] md5andsha1)
        {
            try
            {
                return signer.GenerateRawSignature(privateKey, md5andsha1);
            }
            catch (CryptoException)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}
