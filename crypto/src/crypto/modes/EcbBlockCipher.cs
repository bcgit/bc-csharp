using System;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Implementation of the electronic code book (ECB) mode, which encrypts each block independently of the others.
    /// </summary>
    public class EcbBlockCipher
        : IBlockCipherMode
    {
        internal static IBlockCipherMode GetBlockCipherMode(IBlockCipher blockCipher)
        {
            if (blockCipher is IBlockCipherMode blockCipherMode)
                return blockCipherMode;

            return new EcbBlockCipher(blockCipher);
        }

        private readonly IBlockCipher m_cipher;

        /// <summary>Create a new <see cref="EcbBlockCipher"/>.</summary>
        /// <param name="cipher">The cipher.</param>
        public EcbBlockCipher(IBlockCipher cipher)
        {
            m_cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }

        /// <inheritdoc/>
        public bool IsPartialBlockOkay => false;

        /// <inheritdoc/>
        public string AlgorithmName => m_cipher.AlgorithmName + "/ECB";

        /// <inheritdoc/>
        public int GetBlockSize()
        {
            return m_cipher.GetBlockSize();
        }

        /// <inheritdoc/>
        public IBlockCipher UnderlyingCipher => m_cipher;

        /// <inheritdoc/>
        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            m_cipher.Init(forEncryption, parameters);
        }

        /// <inheritdoc/>
        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            return m_cipher.ProcessBlock(inBuf, inOff, outBuf, outOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            return m_cipher.ProcessBlock(input, output);
        }
#endif

        /// <inheritdoc/>
        public void Reset()
        {
        }
    }
}
