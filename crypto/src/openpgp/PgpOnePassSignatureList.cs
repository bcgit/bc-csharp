namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Holder for a list of PgpOnePassSignature objects.</summary>
    public class PgpOnePassSignatureList
        : PgpObject
    {
        private readonly PgpOnePassSignature[] m_sigs;

        /// <summary>Create a new <see cref="PgpOnePassSignatureList"/>.</summary>
        /// <param name="sig">The signature.</param>
        public PgpOnePassSignatureList(PgpOnePassSignature sig)
        {
            m_sigs = new PgpOnePassSignature[] { sig };
        }

        /// <summary>Create a new <see cref="PgpOnePassSignatureList"/>.</summary>
        /// <param name="sigs">The sigs.</param>
        public PgpOnePassSignatureList(PgpOnePassSignature[] sigs)
        {
            m_sigs = (PgpOnePassSignature[])sigs.Clone();
        }

        public PgpOnePassSignature this[int index] => m_sigs[index];

        /// <summary>Gets the count.</summary>
        public int Count => m_sigs.Length;

        /// <summary>Gets a value indicating whether this is empty.</summary>
        public bool IsEmpty => m_sigs.Length == 0;
    }
}
