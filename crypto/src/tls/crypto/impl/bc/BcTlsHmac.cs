using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsHmac
        : TlsHmac
    {
        private readonly HMac m_hmac;

        internal BcTlsHmac(HMac hmac)
        {
            this.m_hmac = hmac;
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            m_hmac.Init(new KeyParameter(key, keyOff, keyLen));
        }

        public void Update(byte[] input, int inOff, int length)
        {
            m_hmac.BlockUpdate(input, inOff, length);
        }

        public byte[] CalculateMac()
        {
            byte[] rv = new byte[m_hmac.GetMacSize()];
            m_hmac.DoFinal(rv, 0);
            return rv;
        }

        public void CalculateMac(byte[] output, int outOff)
        {
            m_hmac.DoFinal(output, outOff);
        }

        public int InternalBlockSize
        {
            get { return m_hmac.GetUnderlyingDigest().GetByteLength(); }
        }

        public int MacLength
        {
            get { return m_hmac.GetMacSize(); }
        }

        public void Reset()
        {
            m_hmac.Reset();
        }
    }
}
