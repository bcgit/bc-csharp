using System;

namespace Org.BouncyCastle.Pkix
{
    public class CertStatus
    {
        public const int Unrevoked = 11;

        public const int Undetermined = 12;

        private int status = Unrevoked;

        DateTime? revocationDate = null;

        /// <summary>
        /// Returns the revocationDate.
        /// </summary>
         public DateTime? RevocationDate
        {
            get { return revocationDate; }
            set { this.revocationDate = value; }
        }

		/// <summary>
        /// Returns the certStatus.
        /// </summary>
        public int Status
        {
            get { return status; }
            set { this.status = value; }
        }
    }
}
