namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class NodeEntry
    {
        private readonly byte[] m_nodeValue;
        private readonly uint m_nodeHeight;

        internal NodeEntry(byte[] nodeValue, uint nodeHeight)
        {
            m_nodeValue = nodeValue;
            m_nodeHeight = nodeHeight;
        }

        internal uint NodeHeight => m_nodeHeight;

        internal byte[] NodeValue => m_nodeValue;
    }
}
