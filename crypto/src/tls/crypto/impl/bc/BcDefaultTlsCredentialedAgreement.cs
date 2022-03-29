using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summay>Credentialed class generating agreed secrets from a peer's public key for our end of the TLS connection
    /// using the BC light-weight API.</summay>
    public class BcDefaultTlsCredentialedAgreement
        : TlsCredentialedAgreement
    {
        protected readonly TlsCredentialedAgreement m_agreementCredentials;

        public BcDefaultTlsCredentialedAgreement(BcTlsCrypto crypto, Certificate certificate,
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

            if (privateKey is DHPrivateKeyParameters)
            {
                this.m_agreementCredentials = new DHCredentialedAgreement(crypto, certificate,
                    (DHPrivateKeyParameters)privateKey);
            }
            else if (privateKey is ECPrivateKeyParameters)
            {
                this.m_agreementCredentials = new ECCredentialedAgreement(crypto, certificate,
                    (ECPrivateKeyParameters)privateKey);
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: " + Platform.GetTypeName(privateKey));
            }
        }

        public virtual Certificate Certificate
        {
            get { return m_agreementCredentials.Certificate; }
        }

        public virtual TlsSecret GenerateAgreement(TlsCertificate peerCertificate)
        {
            return m_agreementCredentials.GenerateAgreement(peerCertificate);
        }

        private sealed class DHCredentialedAgreement
            : TlsCredentialedAgreement
        {
            private readonly BcTlsCrypto m_crypto;
            private readonly Certificate m_certificate;
            private readonly DHPrivateKeyParameters m_privateKey;

            internal DHCredentialedAgreement(BcTlsCrypto crypto, Certificate certificate,
                DHPrivateKeyParameters privateKey)
            {
                this.m_crypto = crypto;
                this.m_certificate = certificate;
                this.m_privateKey = privateKey;
            }

            public TlsSecret GenerateAgreement(TlsCertificate peerCertificate)
            {
                BcTlsCertificate bcCert = BcTlsCertificate.Convert(m_crypto, peerCertificate);
                DHPublicKeyParameters peerPublicKey = bcCert.GetPubKeyDH();
                return BcTlsDHDomain.CalculateDHAgreement(m_crypto, m_privateKey, peerPublicKey, false);
            }

            public Certificate Certificate
            {
                get { return m_certificate; }
            }
        }

        private sealed class ECCredentialedAgreement
            : TlsCredentialedAgreement
        {
            private readonly BcTlsCrypto m_crypto;
            private readonly Certificate m_certificate;
            private readonly ECPrivateKeyParameters m_privateKey;

            internal ECCredentialedAgreement(BcTlsCrypto crypto, Certificate certificate,
                ECPrivateKeyParameters privateKey)
            {
                this.m_crypto = crypto;
                this.m_certificate = certificate;
                this.m_privateKey = privateKey;
            }

            public TlsSecret GenerateAgreement(TlsCertificate peerCertificate)
            {
                BcTlsCertificate bcCert = BcTlsCertificate.Convert(m_crypto, peerCertificate);
                ECPublicKeyParameters peerPublicKey = bcCert.GetPubKeyEC();
                return BcTlsECDomain.CalculateECDHAgreement(m_crypto, m_privateKey, peerPublicKey);
            }

            public Certificate Certificate
            {
                get { return m_certificate; }
            }
        }
    }
}
