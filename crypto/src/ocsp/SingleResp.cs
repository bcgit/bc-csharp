using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    public class SingleResp
        : X509ExtensionBase
    {
        internal readonly SingleResponse m_resp;

        public SingleResp(SingleResponse resp)
        {
            m_resp = resp ?? throw new ArgumentNullException(nameof(resp));
        }

        public CertificateID GetCertID() => new CertificateID(m_resp.CertId);

        /// <summary>Return the status object for the response - null indicates good.</summary>
        public object GetCertStatus()
        {
            CertStatus s = m_resp.CertStatus;

            if (s.TagNo == 0)
                return null; // good

            if (s.TagNo == 1)
                return new RevokedStatus(RevokedInfo.GetInstance(s.Status));

            return new UnknownStatus();
        }

        public DateTime ThisUpdate => m_resp.ThisUpdate.ToDateTime();

        /// <summary>Return the NextUpdate value.</summary>
        /// <remarks>
        /// This is an optional field so may be returned as null.
        /// </remarks>
        public DateTime? NextUpdate => m_resp.NextUpdate?.ToDateTime();

        public X509Extensions SingleExtensions => m_resp.SingleExtensions;

        protected override X509Extensions GetX509Extensions() => SingleExtensions;
    }
}
