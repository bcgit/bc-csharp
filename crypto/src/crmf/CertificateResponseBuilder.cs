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

        /// <summary>Base constructor.</summary>
        /// <param name="certReqID">The request ID for the response.</param>
        /// <param name="statusInfo">The status info to associate with the response.</param>
        public CertificateResponseBuilder(DerInteger certReqID, PkiStatusInfo statusInfo)
        {
            m_certReqID = certReqID;
            m_statusInfo = statusInfo;
        }

        /// <summary>Specify the certificate to assign to this response (in plaintext).</summary>
        /// <param name="certificate">The X.509 PK certificate to include.</param>
        /// <returns>The current builder.</returns>
        /// <exception cref="InvalidOperationException">A certificate has already been set.</exception>
        public virtual CertificateResponseBuilder WithCertificate(X509Certificate certificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            var cmpCertificate = new CmpCertificate(certificate.CertificateStructure);

            m_certKeyPair = new CertifiedKeyPair(new CertOrEncCert(cmpCertificate));

            return this;
        }

        /// <summary>Specify the certificate to assign to this response (in plaintext).</summary>
        /// <param name="cmpCertificate">The certificate to include.</param>
        /// <returns>The current builder.</returns>
        /// <exception cref="InvalidOperationException">A certificate has already been set.</exception>
        public virtual CertificateResponseBuilder WithCertificate(CmpCertificate cmpCertificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            m_certKeyPair = new CertifiedKeyPair(new CertOrEncCert(cmpCertificate));

            return this;
        }

        /// <summary>Specify the encrypted certificate to assign to this response.</summary>
        /// <param name="encryptedCertificate">The enveloped data holding the encrypted certificate.</param>
        /// <returns>The current builder.</returns>
        /// <exception cref="InvalidOperationException">A certificate has already been set.</exception>
        public virtual CertificateResponseBuilder WithCertificate(CmsEnvelopedData encryptedCertificate)
        {
            if (m_certKeyPair != null)
                throw new InvalidOperationException("certificate in response already set");

            var encryptedKey = new EncryptedKey(encryptedCertificate.EnvelopedData);
            var certOrEncCert = new CertOrEncCert(encryptedKey);

            m_certKeyPair = new CertifiedKeyPair(certOrEncCert);
            return this;
        }

        /// <summary>Specify the response info field on the response.</summary>
        /// <param name="responseInfo">The response info.</param>
        /// <returns>The current builder.</returns>
        /// <exception cref="InvalidOperationException">The response info has already been set.</exception>
        public virtual CertificateResponseBuilder WithResponseInfo(byte[] responseInfo)
        {
            if (m_rspInfo != null)
                throw new InvalidOperationException("response info already set");

            m_rspInfo = DerOctetString.FromContents(responseInfo);

            return this;
        }

        /// <summary>Build the response.</summary>
        public virtual CertificateResponse Build() =>
            new CertificateResponse(new CertResponse(m_certReqID, m_statusInfo, m_certKeyPair, m_rspInfo));
    }
}
