using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Builder for <see cref="CertificateReqMessages"/>.</summary>
    public class CertificateReqMessagesBuilder
    {
        private readonly List<CertReqMsg> m_requests = new List<CertReqMsg>();

        /// <summary>Create an empty builder.</summary>
        public CertificateReqMessagesBuilder()
        {
        }

        /// <summary>Add a request message.</summary>
        /// <param name="request">The request to add.</param>
        public virtual void AddRequest(CertificateRequestMessage request) => m_requests.Add(request.ToAsn1Structure());

        /// <summary>Build the messages from the requests added so far, then clear the builder.</summary>
        public virtual CertificateReqMessages Build()
        {
            CertificateReqMessages certificateReqMessages = new CertificateReqMessages(
                new CertReqMessages(m_requests.ToArray()));

            m_requests.Clear();

            return certificateReqMessages;
        }
    }
}
