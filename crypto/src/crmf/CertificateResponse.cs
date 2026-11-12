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

        /// <summary>Wrap a CertResponse structure.</summary>
        /// <param name="certResponse">The ASN.1 structure.</param>
        public CertificateResponse(CertResponse certResponse)
        {
            m_certResponse = certResponse;
        }

        /// <summary>Gets whether the response contains an encrypted certificate.</summary>
        public virtual bool HasEncryptedCertificate =>
            m_certResponse.CertifiedKeyPair.CertOrEncCert.HasEncryptedCertificate;

        /// <summary>Return a CmsEnvelopedData representing the encrypted certificate contained in the response.
        /// </summary>
        /// <returns>The enveloped data, if an encrypted certificate is present.</returns>
        /// <exception cref="InvalidOperationException">
        /// No encrypted certificate is present, or it is encrypted for more than one recipient.
        /// </exception>
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

        /// <summary>Return the CmpCertificate representing the plaintext certificate in the response.</summary>
        /// <returns>The certificate, if a plaintext certificate is present.</returns>
        /// <exception cref="InvalidOperationException">No plaintext certificate is present.</exception>
        public virtual CmpCertificate GetCertificate()
        {
            if (HasEncryptedCertificate)
                throw new InvalidOperationException("plaintext certificate asked for, none found");

            return m_certResponse.CertifiedKeyPair.CertOrEncCert.Certificate;
        }

        /// <summary>Return this object's underlying ASN.1 structure.</summary>
        public virtual CertResponse ToAsn1Structure() => m_certResponse;
    }
}
