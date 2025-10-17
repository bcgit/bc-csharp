namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class SK
    {
        private readonly byte[] m_seed;
        private readonly byte[] m_prf;

        internal SK(byte[] seed, byte[] prf)
        {
            m_seed = seed;
            m_prf = prf;
        }

        internal byte[] Prf => m_prf;

        internal byte[] Seed => m_seed;
    }
}
