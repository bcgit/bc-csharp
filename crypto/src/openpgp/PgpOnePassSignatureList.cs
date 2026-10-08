namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Holder for a list of PgpOnePassSignature objects.</summary>
    public class PgpOnePassSignatureList
        : PgpObject
    {
        private readonly PgpOnePassSignature[] m_sigs;

        public PgpOnePassSignatureList(PgpOnePassSignature sig)
        {
            m_sigs = new PgpOnePassSignature[] { sig };
        }

        public PgpOnePassSignatureList(PgpOnePassSignature[] sigs)
            : this(sigs, 0)
        {
        }

        internal PgpOnePassSignatureList(PgpOnePassSignature[] sigs, int unsupportedCount)
        {
            m_sigs = (PgpOnePassSignature[])sigs.Clone();
            UnsupportedCount = unsupportedCount;
        }

        public PgpOnePassSignature this[int index] => m_sigs[index];

        public int Count => m_sigs.Length;

        public bool IsEmpty => m_sigs.Length == 0;

        /// <summary>
        /// The number of one-pass signatures of unsupported versions, and of malformed ones, that the list leaves out
        /// (RFC 9580 5.2.5). Their signatures still follow the signed data, which matters to a consumer that checks
        /// the structure of the message (10.3).
        /// </summary>
        public int UnsupportedCount { get; }
    }
}
