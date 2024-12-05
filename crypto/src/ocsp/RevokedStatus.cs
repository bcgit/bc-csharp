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

		public RevokedStatus(RevokedInfo revokedInfo)
		{
			m_revokedInfo = revokedInfo;
		}

		public RevokedStatus(DateTime revocationDate)
		{
			var revocationTime = Rfc5280Asn1Utilities.CreateGeneralizedTime(revocationDate);

            m_revokedInfo = new RevokedInfo(revocationTime);
		}

        public RevokedStatus(DateTime revocationDate, int reason)
		{
            var revocationTime = Rfc5280Asn1Utilities.CreateGeneralizedTime(revocationDate);

            m_revokedInfo = new RevokedInfo(revocationTime, new CrlReason(reason));
		}

		public DateTime RevocationTime
		{
			get { return m_revokedInfo.RevocationTime.ToDateTime(); }
		}

		public bool HasRevocationReason
		{
			get { return m_revokedInfo.RevocationReason != null; }
		}

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
