using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsHmac
        : TlsHmac
    {
        private readonly HMac m_hmac;

        internal BcTlsHmac(HMac hmac)
        {
            m_hmac = hmac;
        }

        public void SetKey(byte[] key, int keyOff, int keyLen) => m_hmac.Init(new KeyParameter(key, keyOff, keyLen));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void SetKey(ReadOnlySpan<byte> key) => m_hmac.Init(new KeyParameter(key));
#endif

        public void Update(byte[] input, int inOff, int length) => m_hmac.BlockUpdate(input, inOff, length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input) => m_hmac.BlockUpdate(input);
#endif

        public byte[] CalculateMac() => MacUtilities.DoFinal(m_hmac);

        public void CalculateMac(byte[] output, int outOff) => m_hmac.DoFinal(output, outOff);

        public int InternalBlockSize => m_hmac.GetUnderlyingDigest().GetByteLength();

        public int MacLength => m_hmac.GetMacSize();

        public void Reset() => m_hmac.Reset();
    }
}
