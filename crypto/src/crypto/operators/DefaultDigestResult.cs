using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The result of a digest calculation.</summary>
    public sealed class DefaultDigestResult
        : IBlockResult
    {
        private readonly IDigest m_digest;

        /// <summary>Create a new <see cref="DefaultDigestResult"/>.</summary>
        /// <param name="digest">The digest.</param>
        public DefaultDigestResult(IDigest digest)
        {
            m_digest = digest;
        }

        /// <inheritdoc/>
        public byte[] Collect() => DigestUtilities.DoFinal(m_digest);

        /// <inheritdoc/>
        public int Collect(byte[] buf, int off) => m_digest.DoFinal(buf, off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int Collect(Span<byte> output) => m_digest.DoFinal(output);
#endif

        /// <inheritdoc/>
        public int GetMaxResultLength() => m_digest.GetDigestSize();
    }
}
