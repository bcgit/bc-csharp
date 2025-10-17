namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class IndexedDigest
    {
        private readonly ulong m_idxTree;
        private readonly uint m_idxLeaf;
        private readonly byte[] m_digest;

        internal IndexedDigest(ulong idxTree, uint idxLeaf, byte[] digest)
        {
            m_idxTree = idxTree;
            m_idxLeaf = idxLeaf;
            m_digest = digest;
        }

        internal byte[] Digest => m_digest;

        internal uint IdxLeaf => m_idxLeaf;

        internal ulong IdxTree => m_idxTree;
    }
}
