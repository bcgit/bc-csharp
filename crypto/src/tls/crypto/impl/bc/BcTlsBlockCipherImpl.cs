using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsBlockCipherImpl
        : TlsBlockCipherImpl
    {
        private readonly bool m_isEncrypting;
        private readonly IBlockCipher m_cipher;

        private KeyParameter key;

        internal BcTlsBlockCipherImpl(IBlockCipher cipher, bool isEncrypting)
        {
            this.m_cipher = cipher;
            this.m_isEncrypting = isEncrypting;
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            this.key = new KeyParameter(key, keyOff, keyLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void SetKey(ReadOnlySpan<byte> key)
        {
            this.key = new KeyParameter(key);
        }
#endif

        public void Init(byte[] iv, int ivOff, int ivLen)
        {
            m_cipher.Init(m_isEncrypting, new ParametersWithIV(key, iv, ivOff, ivLen));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Init(ReadOnlySpan<byte> iv)
        {
            m_cipher.Init(m_isEncrypting, new ParametersWithIV(key, iv));
        }
#endif

        public int DoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            int blockSize = m_cipher.GetBlockSize();

            for (int i = 0; i < inputLength; i += blockSize)
            {
                m_cipher.ProcessBlock(input, inputOffset + i, output, outputOffset + i);
            }

            return inputLength;
        }

        public int GetBlockSize()
        {
            return m_cipher.GetBlockSize();
        }
    }
}
