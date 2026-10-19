using System;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Holds the revocation status determined for a certificate while its CRLs are checked.</summary>
    [Obsolete("Will be removed")]
    public class CertStatus
    {
        /// <summary>The certificate has not been found to be revoked.</summary>
        public const int Unrevoked = 11;

        /// <summary>The revocation status could not be determined.</summary>
        public const int Undetermined = 12;

        private int status = Unrevoked;

        DateTime? revocationDate = null;

        /// <summary>Gets or sets the date of revocation, or null if the certificate is not revoked.</summary>
        public DateTime? RevocationDate
        {
            get { return revocationDate; }
            set { this.revocationDate = value; }
        }

        /// <summary>
        /// Gets or sets the status: <see cref="Unrevoked"/>, <see cref="Undetermined"/> or a CRL reason code.
        /// </summary>
        public int Status
        {
            get { return status; }
            set { this.status = value; }
        }
    }
}
