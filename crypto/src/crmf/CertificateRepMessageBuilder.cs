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

        /// <summary>
        /// Base constructor which can accept 0 or more certificates representing the CA plus its chain.
        /// </summary>
        /// <param name="caCerts">The CA public key and its support certificates (optional).</param>
        public CertificateRepMessageBuilder(params X509Certificate[] caCerts)
        {
            m_caCerts = Array.ConvertAll(caCerts, caCert => new CmpCertificate(caCert.CertificateStructure));
        }

        /// <summary>Add a certificate response.</summary>
        /// <param name="response">The response to add.</param>
        /// <returns>This builder.</returns>
        public virtual CertificateRepMessageBuilder AddCertificateResponse(CertificateResponse response)
        {
            m_responses.Add(response.ToAsn1Structure());
            return this;
        }

        /// <summary>Build the message from the responses added so far, then clear the responses.</summary>
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
