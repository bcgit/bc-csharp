using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>A single certificate status request within an <see cref="OcspReq"/>.</summary>
    public class Req
        : X509ExtensionBase
    {
        private readonly Request m_req;

        /// <summary>Create from an ASN.1 Request structure.</summary>
        /// <param name="req">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="req"/> is null.</exception>
        public Req(Request req)
        {
            m_req = req ?? throw new ArgumentNullException(nameof(req));
        }

        /// <summary>Return the identifier of the certificate this request is about.</summary>
        public CertificateID GetCertID() => new CertificateID(m_req.ReqCert);

        /// <summary>Gets the extensions specific to this request, or null if there are none.</summary>
        public X509Extensions SingleRequestExtensions => m_req.SingleRequestExtensions;

        protected override X509Extensions GetX509Extensions() => SingleRequestExtensions;
    }
}
