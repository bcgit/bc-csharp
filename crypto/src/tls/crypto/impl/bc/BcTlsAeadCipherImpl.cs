using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal class BcTlsAeadCipherImpl
        : TlsAeadCipherImpl
    {
        private readonly bool m_isEncrypting;
        internal readonly IAeadCipher m_cipher;

        private KeyParameter key;

        internal BcTlsAeadCipherImpl(IAeadCipher cipher, bool isEncrypting)
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

        public void Init(byte[] nonce, int macSize, byte[] additionalData)
        {
            m_cipher.Init(m_isEncrypting, new AeadParameters(key, macSize * 8, nonce, additionalData));
        }

        public int GetOutputSize(int inputLength)
        {
            return m_cipher.GetOutputSize(inputLength);
        }

        public virtual int DoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            int len = m_cipher.ProcessBytes(input, inputOffset, inputLength, output, outputOffset);

            try
            {
                len += m_cipher.DoFinal(output, outputOffset + len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
            }

            return len;
        }

        public virtual int DoFinal(byte[] additionalData, byte[] input, int inputOffset, int inputLength, byte[] output,
            int outputOffset)
        {
            if (additionalData != null)
            {
                m_cipher.ProcessAadBytes(additionalData, 0, additionalData.Length);
            }

            return DoFinal(input, inputOffset, inputLength, output, outputOffset);
        }

        public void Reset()
        {
        }
    }
}
