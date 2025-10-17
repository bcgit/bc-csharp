namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class PK
    {
        private readonly byte[] m_seed;
        private readonly byte[] m_root;

        internal PK(byte[] seed, byte[] root)
        {
            m_seed = seed;
            m_root = root;
        }

        internal byte[] Root => m_root;

        internal byte[] Seed => m_seed;
    }
}
