using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>The status of a single certificate within a basic OCSP response.</summary>
    public class SingleResp
        : X509ExtensionBase
    {
        internal readonly SingleResponse m_resp;

        /// <summary>Create from an ASN.1 SingleResponse structure.</summary>
        /// <param name="resp">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="resp"/> is null.</exception>
        public SingleResp(SingleResponse resp)
        {
            m_resp = resp ?? throw new ArgumentNullException(nameof(resp));
        }

        /// <summary>Return the identifier of the certificate this response is about.</summary>
        public CertificateID GetCertID() => new CertificateID(m_resp.CertId);

        /// <summary>Return the status object for the response - null indicates good.</summary>
        /// <returns>
        /// null if the certificate is good, a <see cref="RevokedStatus"/> if it has been revoked, otherwise an
        /// <see cref="UnknownStatus"/>.
        /// </returns>
        public object GetCertStatus()
        {
            CertStatus s = m_resp.CertStatus;

            if (s.TagNo == 0)
                return null; // good

            if (s.TagNo == 1)
                return new RevokedStatus(RevokedInfo.GetInstance(s.Status));

            return new UnknownStatus();
        }

        /// <summary>Gets the time at which the status being indicated is known to be correct.</summary>
        public DateTime ThisUpdate => m_resp.ThisUpdate.ToDateTime();

        /// <summary>Return the NextUpdate value.</summary>
        /// <remarks>
        /// This is an optional field so may be returned as null.
        /// </remarks>
        public DateTime? NextUpdate => m_resp.NextUpdate?.ToDateTime();

        /// <summary>Gets the extensions specific to this response, or null if there are none.</summary>
        public X509Extensions SingleExtensions => m_resp.SingleExtensions;

        protected override X509Extensions GetX509Extensions() => SingleExtensions;
    }
}
