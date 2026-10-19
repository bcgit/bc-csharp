using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Wrapper for the RevokedInfo object</summary>
    public class RevokedStatus
        : CertificateStatus
    {
        private readonly RevokedInfo m_revokedInfo;

        /// <summary>Create from an existing ASN.1 RevokedInfo structure.</summary>
        /// <param name="revokedInfo">The ASN.1 structure.</param>
        public RevokedStatus(RevokedInfo revokedInfo)
        {
            m_revokedInfo = revokedInfo;
        }

        /// <summary>Create a status with a revocation time and no reason.</summary>
        /// <param name="revocationDate">The time at which the certificate was revoked.</param>
        public RevokedStatus(DateTime revocationDate)
        {
            var revocationTime = Rfc5280Asn1Utilities.CreateGeneralizedTime(revocationDate);

            m_revokedInfo = new RevokedInfo(revocationTime);
        }

        /// <summary>Create a status with a revocation time and reason.</summary>
        /// <param name="revocationDate">The time at which the certificate was revoked.</param>
        /// <param name="reason">The CRLReason code for the revocation.</param>
        public RevokedStatus(DateTime revocationDate, int reason)
        {
            var revocationTime = Rfc5280Asn1Utilities.CreateGeneralizedTime(revocationDate);

            m_revokedInfo = new RevokedInfo(revocationTime, new CrlReason(reason));
        }

        /// <summary>Gets the time at which the certificate was revoked.</summary>
        public DateTime RevocationTime => m_revokedInfo.RevocationTime.ToDateTime();

        /// <summary>Gets whether a revocation reason is available.</summary>
        public bool HasRevocationReason => m_revokedInfo.RevocationReason != null;

        /// <summary>Return the revocation reason, if there is one.</summary>
        /// <remarks>This field is optional; test for it with <see cref="HasRevocationReason"/> first.</remarks>
        /// <returns>The revocation reason, if available.</returns>
        /// <exception cref="InvalidOperationException">If no revocation reason is available.</exception>
        public int RevocationReason
        {
            get
            {
                if (m_revokedInfo.RevocationReason == null)
                    throw new InvalidOperationException("attempt to get a reason where none is available");

                return m_revokedInfo.RevocationReason.IntValueExact;
            }
        }
    }
}
