using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>Builder for the RevRepContent structure of RFC 4210, the body of a revocation response.</summary>
    public class RevRepContentBuilder
    {
        private readonly Asn1EncodableVector m_status = new Asn1EncodableVector();
        private readonly Asn1EncodableVector m_revCerts = new Asn1EncodableVector();
        private readonly Asn1EncodableVector m_crls = new Asn1EncodableVector();

        /// <summary>Add a status to the response.</summary>
        /// <param name="status">The status.</param>
        /// <returns>This builder.</returns>
        public virtual RevRepContentBuilder Add(PkiStatusInfo status)
        {
            m_status.Add(status);
            return this;
        }

        /// <summary>Add a status and the certificate ID it applies to.</summary>
        /// <param name="status">The status.</param>
        /// <param name="certId">The certificate ID.</param>
        /// <returns>This builder.</returns>
        public virtual RevRepContentBuilder Add(PkiStatusInfo status, CertId certId)
        {
            if (m_status.Count != m_revCerts.Count)
                throw new InvalidOperationException("status and revCerts sequence must be in common order");

            m_status.Add(status);
            m_revCerts.Add(certId);
            return this;
        }

        /// <summary>Add a CRL to the response.</summary>
        /// <param name="crl">The CRL.</param>
        /// <returns>This builder.</returns>
        public virtual RevRepContentBuilder AddCrl(CertificateList crl)
        {
            m_crls.Add(crl);
            return this;
        }

        /// <summary>Build the response content.</summary>
        /// <returns>The new content.</returns>
        public virtual RevRepContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);

            v.Add(new DerSequence(m_status));

            if (m_revCerts.Count != 0)
            {
                v.Add(new DerTaggedObject(true, 0, new DerSequence(m_revCerts)));
            }

            if (m_crls.Count != 0)
            {
                v.Add(new DerTaggedObject(true, 1, new DerSequence(m_crls)));
            }

            return RevRepContent.GetInstance(new DerSequence(v));
        }
    }
}
