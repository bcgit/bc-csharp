namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for RC2, holding the key and the effective key size.</summary>
    public class RC2Parameters
        : KeyParameter
    {
        private readonly int m_bits;

        /// <summary>Create a new <see cref="RC2Parameters"/>.</summary>
        /// <param name="key">The key.</param>
        public RC2Parameters(byte[] key)
            : this(key, (key.Length > 128) ? 1024 : (key.Length * 8))
        {
        }

        /// <summary>Create a new <see cref="RC2Parameters"/>.</summary>
        /// <param name="key">The key.</param>
        /// <param name="keyOff">The key off.</param>
        /// <param name="keyLen">The key len.</param>
        public RC2Parameters(byte[] key, int keyOff, int keyLen)
            : this(key, keyOff, keyLen, (keyLen > 128) ? 1024 : (keyLen * 8))
        {
        }

        /// <summary>Create a new <see cref="RC2Parameters"/>.</summary>
        /// <param name="key">The key.</param>
        /// <param name="bits">The bits.</param>
        public RC2Parameters(byte[] key, int bits)
            : base(key)
        {
            m_bits = bits;
        }

        /// <summary>Create a new <see cref="RC2Parameters"/>.</summary>
        /// <param name="key">The key.</param>
        /// <param name="keyOff">The key off.</param>
        /// <param name="keyLen">The key len.</param>
        /// <param name="bits">The bits.</param>
        public RC2Parameters(byte[] key, int keyOff, int keyLen, int bits)
            : base(key, keyOff, keyLen)
        {
            m_bits = bits;
        }

        /// <summary>Gets the effective key bits.</summary>
        public int EffectiveKeyBits => m_bits;
    }
}
