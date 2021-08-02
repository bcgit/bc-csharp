using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>HMAC implementation based on original internet draft for HMAC (RFC 2104).</summary>
    /// <remarks>
    /// The difference is that padding is concatenated versus XORed with the key, e.g:
    /// <code>H(K + opad, H(K + ipad, text))</code>
    /// </remarks>
    internal class BcSsl3Hmac
        : TlsHmac
    {
        private const byte IPAD_BYTE = (byte)0x36;
        private const byte OPAD_BYTE = (byte)0x5C;

        private static readonly byte[] IPAD = GenPad(IPAD_BYTE, 48);
        private static readonly byte[] OPAD = GenPad(OPAD_BYTE, 48);

        private readonly IDigest m_digest;
        private readonly int m_padLength;

        private byte[] m_secret;

        /// <summary>Base constructor for one of the standard digest algorithms for which the byteLength is known.
        /// </summary>
        /// <remarks>
        /// Behaviour is undefined for digests other than MD5 or SHA1.
        /// </remarks>
        /// <param name="digest">the digest.</param>
        internal BcSsl3Hmac(IDigest digest)
        {
            this.m_digest = digest;

            if (digest.GetDigestSize() == 20)
            {
                this.m_padLength = 40;
            }
            else
            {
                this.m_padLength = 48;
            }
        }

        public virtual void SetKey(byte[] key, int keyOff, int keyLen)
        {
            this.m_secret = TlsUtilities.CopyOfRangeExact(key, keyOff, keyOff + keyLen);

            Reset();
        }

        public virtual void Update(byte[] input, int inOff, int len)
        {
            m_digest.BlockUpdate(input, inOff, len);
        }

        public virtual byte[] CalculateMac()
        {
            byte[] result = new byte[m_digest.GetDigestSize()];
            DoFinal(result, 0);
            return result;
        }

        public virtual void CalculateMac(byte[] output, int outOff)
        {
            DoFinal(output, outOff);
        }

        public virtual int InternalBlockSize
        {
            get { return m_digest.GetByteLength(); }
        }

        public virtual int MacLength
        {
            get { return m_digest.GetDigestSize(); }
        }

        /**
         * Reset the mac generator.
         */
        public virtual void Reset()
        {
            m_digest.Reset();
            m_digest.BlockUpdate(m_secret, 0, m_secret.Length);
            m_digest.BlockUpdate(IPAD, 0, m_padLength);
        }

        private void DoFinal(byte[] output, int outOff)
        {
            byte[] tmp = new byte[m_digest.GetDigestSize()];
            m_digest.DoFinal(tmp, 0);

            m_digest.BlockUpdate(m_secret, 0, m_secret.Length);
            m_digest.BlockUpdate(OPAD, 0, m_padLength);
            m_digest.BlockUpdate(tmp, 0, tmp.Length);

            m_digest.DoFinal(output, outOff);

            Reset();
        }

        private static byte[] GenPad(byte b, int count)
        {
            byte[] padding = new byte[count];
            Arrays.Fill(padding, b);
            return padding;
        }
    }
}
