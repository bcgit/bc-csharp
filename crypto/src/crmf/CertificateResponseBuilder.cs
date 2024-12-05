using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Builder for CertificateResponse objects (the CertResponse CRMF equivalent).</summary>
    public class CertificateResponseBuilder
    {
        private readonly DerInteger m_certReqID;
        private readonly PkiStatusInfo m_statusInfo;

        private CertifiedKeyPair m_certKeyPair;
        private Asn1OctetString m_rspInfo;

        /**
         * Base constructor.
         *
         * @param certReqId the request ID for the response.
         * @param statusInfo the status info to associate with the response.
         */
        public CertificateResponseBuilder(DerInteger certReqID, PkiStatusInfo statusInfo)
        {
            m_certReqID = certReqID;
            m_statusInfo = statusInfo;
        }

        /**
         * Specify the certificate to assign to this response (in plaintext).
         *
         * @param certificate the X.509 PK certificate to include.
         * @return the current builder.
         */
        public virtual CertificateResponseBuilder WithCertificate(X509Certificate certificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            var cmpCertificate = new CmpCertificate(certificate.CertificateStructure);

            m_certKeyPair = new CertifiedKeyPair(new CertOrEncCert(cmpCertificate));

            return this;
        }

        /**
         * Specify the certificate to assign to this response (in plaintext).
         *
         * @param cmpCertificate the X.509 PK certificate to include.
         * @return the current builder.
         */
        public virtual CertificateResponseBuilder WithCertificate(CmpCertificate cmpCertificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            m_certKeyPair = new CertifiedKeyPair(new CertOrEncCert(cmpCertificate));

            return this;
        }

        /**
         * Specify the encrypted certificate to assign to this response (in plaintext).
         *
         * @param encryptedCertificate an encrypted
         * @return the current builder.
         */
        public virtual CertificateResponseBuilder WithCertificate(CmsEnvelopedData encryptedCertificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            var encryptedKey = new EncryptedKey(EnvelopedData.GetInstance(encryptedCertificate.ContentInfo.Content));

            m_certKeyPair = new CertifiedKeyPair(new CertOrEncCert(encryptedKey));

            return this;
        }

        /**
         * Specify the response info field on the response.
         *
         * @param responseInfo a response info string.
         * @return the current builder.
         */
        public virtual CertificateResponseBuilder WithResponseInfo(byte[] responseInfo)
        {
            if (m_rspInfo != null)
                throw new InvalidOperationException("response info already set");

            m_rspInfo = DerOctetString.FromContents(responseInfo);

            return this;
        }

        public virtual CertificateResponse Build() =>
            new CertificateResponse(new CertResponse(m_certReqID, m_statusInfo, m_certKeyPair, m_rspInfo));
    }
}
