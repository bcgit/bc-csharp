using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultDigestResult
        : IBlockResult
    {
        private readonly IDigest m_digest;

        public DefaultDigestResult(IDigest digest)
        {
            m_digest = digest;
        }

        public byte[] Collect() => DigestUtilities.DoFinal(m_digest);

        public int Collect(byte[] buf, int off) => m_digest.DoFinal(buf, off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output) => m_digest.DoFinal(output);
#endif

        public int GetMaxResultLength() => m_digest.GetDigestSize();
    }
}
