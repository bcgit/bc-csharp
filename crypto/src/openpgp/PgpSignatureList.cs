using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>A list of PGP signatures - normally in the signature block after literal data.</remarks>
    public class PgpSignatureList
		: PgpObject
    {
        private readonly PgpSignature[] sigs;

		public PgpSignatureList(
            PgpSignature[] sigs)
            : this(sigs, 0)
        {
        }

        internal PgpSignatureList(PgpSignature[] sigs, int unsupportedCount)
        {
            this.sigs = (PgpSignature[])sigs.Clone();
            UnsupportedCount = unsupportedCount;
        }

		public PgpSignatureList(
            PgpSignature sig)
        {
			this.sigs = new PgpSignature[]{ sig };
        }

		public PgpSignature this[int index]
		{
			get { return sigs[index]; }
		}

		public int Count
		{
			get { return sigs.Length; }
		}

		public bool IsEmpty
        {
			get { return (sigs.Length == 0); }
        }

        /// <summary>
        /// The number of signatures of unsupported versions, and of malformed ones, that the list leaves out (RFC
        /// 9580 5.2.5), which matters to a consumer that pairs signatures with one-pass signatures (5.4).
        /// </summary>
        public int UnsupportedCount { get; }
    }
}
