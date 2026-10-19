using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The default digest calculator, which feeds the data written to it into a digest.</summary>
    public sealed class DefaultDigestCalculator
        : IStreamCalculator<IBlockResult>
    {
        private readonly DigestSink m_digestSink;

        /// <summary>Create a new <see cref="DefaultDigestCalculator"/>.</summary>
        /// <param name="digest">The digest.</param>
        public DefaultDigestCalculator(IDigest digest)
        {
            m_digestSink = new DigestSink(digest);
        }

        public Stream Stream => m_digestSink;

        /// <inheritdoc/>
        public IBlockResult GetResult() => new DefaultDigestResult(m_digestSink.Digest);
    }
}
