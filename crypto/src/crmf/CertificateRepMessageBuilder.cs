using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Builder for a CertificateRepMessage.</summary>
    public class CertificateRepMessageBuilder
    {
        private readonly List<CertResponse> m_responses = new List<CertResponse>();
        private readonly CmpCertificate[] m_caCerts;

        /**
         * Base constructor which can accept 0 or more certificates representing the CA plus its chain.
         *
         * @param caCerts the CA public key and it's support certificates (optional)
         */
        public CertificateRepMessageBuilder(params X509Certificate[] caCerts)
        {
            m_caCerts = Array.ConvertAll(caCerts, caCert => new CmpCertificate(caCert.CertificateStructure));
        }

        public virtual CertificateRepMessageBuilder AddCertificateResponse(CertificateResponse response)
        {
            m_responses.Add(response.ToAsn1Structure());
            return this;
        }

        public virtual CertificateRepMessage Build()
        {
            var caPubs = m_caCerts;
            if (caPubs.Length < 1)
            {
                // older versions of CertRepMessage need null if no caCerts.
                caPubs = null;
            }

            CertRepMessage repMessage = new CertRepMessage(caPubs, m_responses.ToArray());

            m_responses.Clear();

            return new CertificateRepMessage(repMessage);
        }
    }
}
