namespace Org.BouncyCastle.Crypto.Parameters
{
    public class RC2Parameters
        : KeyParameter
    {
        private readonly int m_bits;

        public RC2Parameters(byte[] key)
            : this(key, (key.Length > 128) ? 1024 : (key.Length * 8))
        {
        }

        public RC2Parameters(byte[] key, int keyOff, int keyLen)
            : this(key, keyOff, keyLen, (keyLen > 128) ? 1024 : (keyLen * 8))
        {
        }

        public RC2Parameters(byte[] key, int bits)
            : base(key)
        {
            m_bits = bits;
        }

        public RC2Parameters(byte[] key, int keyOff, int keyLen, int bits)
            : base(key, keyOff, keyLen)
        {
            m_bits = bits;
        }

        public int EffectiveKeyBits => m_bits;
    }
}
