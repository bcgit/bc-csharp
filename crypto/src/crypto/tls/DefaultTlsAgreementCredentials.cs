using System;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class DefaultTlsAgreementCredentials
        : TlsAgreementCredentials
    {
        protected Certificate certificate;
        protected AsymmetricKeyParameter privateKey;

        protected IBasicAgreement basicAgreement;
        protected bool truncateAgreement;

        public DefaultTlsAgreementCredentials(Certificate certificate, AsymmetricKeyParameter privateKey)
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

            if (privateKey is DHPrivateKeyParameters)
            {
                basicAgreement = new DHBasicAgreement();
                truncateAgreement = true;
            }
            else if (privateKey is ECPrivateKeyParameters)
            {
                basicAgreement = new ECDHBasicAgreement();
                truncateAgreement = false;
            }
            else
            {
                throw new ArgumentException("type not supported: "
                    + privateKey.GetType().FullName, "clientPrivateKey");
            }

            this.certificate = certificate;
            this.privateKey = privateKey;
        }

        public virtual Certificate Certificate
        {
            get { return certificate; }
        }

        public virtual byte[] GenerateAgreement(AsymmetricKeyParameter serverPublicKey)
        {
            basicAgreement.Init(privateKey);
            BigInteger agreementValue = basicAgreement.CalculateAgreement(serverPublicKey);
            if (truncateAgreement)
            {
                return BigIntegers.AsUnsignedByteArray(agreementValue);
            }
            return BigIntegers.AsUnsignedByteArray(basicAgreement.GetFieldSize(), agreementValue);
        }
    }
}
