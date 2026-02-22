using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal sealed class Shake256RandomGenerator
    {
        private readonly ShakeDigest m_digest = new ShakeDigest(256);

        public Shake256RandomGenerator(byte[] seed, byte domain)
            : this(seed, 0, seed.Length, domain)
        {
        }

        public Shake256RandomGenerator(byte[] seed, int off, int len, byte domain)
        {
            Init(seed, off, len, domain);
        }

        public void Init(byte[] seed, int off, int len, byte domain)
        {
            Arrays.ValidateSegment(seed, off, len);

            m_digest.Reset();
            m_digest.BlockUpdate(seed, off, len);
            m_digest.Update(domain);
        }

        public void NextBytes(byte[] bytes) => NextBytes(bytes, 0, bytes.Length);

        public void NextBytes(byte[] bytes, int start, int len) => m_digest.Output(bytes, start, len);

        public void XofGetBytes(byte[] output, int outLen)
        {
            int remainder = outLen & 7;
            int tmpLen = outLen - remainder;
            m_digest.Output(output, 0, tmpLen);
            if (remainder != 0)
            {
                byte[] tmp = new byte[8];
                m_digest.Output(tmp, 0, 8);
                Array.Copy(tmp, 0, output, tmpLen, remainder);
            }
        }
    }
}
