using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>High level wrapper for the CertResponse CRMF structure.</summary>
    public class CertificateResponse
    {
        private readonly CertResponse m_certResponse;

        public CertificateResponse(CertResponse certResponse)
        {
            m_certResponse = certResponse;
        }

        /**
         * Return true if the response contains an encrypted certificate.
         *
         * @return true if certificate in response encrypted, false otherwise.
         */
        public virtual bool HasEncryptedCertificate =>
            m_certResponse.CertifiedKeyPair.CertOrEncCert.HasEncryptedCertificate;

        /**
         * Return a CMSEnvelopedData representing the encrypted certificate contained in the response.
         *
         * @return a CMEEnvelopedData if an encrypted certificate is present.
         * @throws IllegalStateException if no encrypted certificate is present, or there is an issue with the enveloped data.
         */
        public virtual CmsEnvelopedData GetEncryptedCertificate()
        {
            if (!HasEncryptedCertificate)
                throw new InvalidOperationException("encrypted certificate asked for, none found");

            CertifiedKeyPair receivedKeyPair = m_certResponse.CertifiedKeyPair;

            var contentInfo = new Asn1.Cms.ContentInfo(PkcsObjectIdentifiers.EnvelopedData,
                receivedKeyPair.CertOrEncCert.EncryptedCert.Value);

            CmsEnvelopedData envelopedData = new CmsEnvelopedData(contentInfo);

            if (envelopedData.GetRecipientInfos().Count != 1)
                throw new InvalidOperationException("data encrypted for more than one recipient");

            return envelopedData;
        }

        // TODO[crmf]
#if false
        /**
         * Return the CMPCertificate representing the plaintext certificate in the response.
         *
         * @return a CMPCertificate if a plaintext certificate is present.
         * @throws IllegalStateException if no plaintext certificate is present.
         */
        public virtual CmpCertificate GetCertificate(Recipient recipient)
        {
            CmsEnvelopedData encryptedCert = GetEncryptedCertificate();

            RecipientInformationStore recipients = encryptedCert.GetRecipientInfos();

            var c = recipients.GetRecipients();

            RecipientInformation recInfo = c[0];

            return CmpCertificate.GetInstance(recInfo.GetContent(recipient));
        }
#endif

        /**
         * Return the CMPCertificate representing the plaintext certificate in the response.
         *
         * @return a CMPCertificate if a plaintext certificate is present.
         * @throws IllegalStateException if no plaintext certificate is present.
         */
        public virtual CmpCertificate GetCertificate()
        {
            if (HasEncryptedCertificate)
                throw new InvalidOperationException("plaintext certificate asked for, none found");

            return m_certResponse.CertifiedKeyPair.CertOrEncCert.Certificate;
        }

        /**
         * Return this object's underlying ASN.1 structure.
         *
         * @return a CertResponse
         */
        public virtual CertResponse ToAsn1Structure() => m_certResponse;
    }
}
