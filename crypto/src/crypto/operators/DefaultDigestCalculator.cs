using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultDigestCalculator
        : IStreamCalculator<IBlockResult>
    {
        private readonly DigestSink m_digestSink;

        public DefaultDigestCalculator(IDigest digest)
        {
            m_digestSink = new DigestSink(digest);
        }

        public Stream Stream => m_digestSink;

        public IBlockResult GetResult() => new DefaultDigestResult(m_digestSink.Digest);
    }
}
