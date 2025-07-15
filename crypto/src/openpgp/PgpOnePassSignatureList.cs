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
        {
            m_sigs = (PgpOnePassSignature[])sigs.Clone();
        }

        public PgpOnePassSignature this[int index] => m_sigs[index];

        public int Count => m_sigs.Length;

        public bool IsEmpty => m_sigs.Length == 0;
    }
}
