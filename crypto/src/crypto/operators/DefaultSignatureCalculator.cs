using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The default signature calculator, which feeds the data written to it into a signer.</summary>
    // TODO[api] sealed
    public class DefaultSignatureCalculator
        : IStreamCalculator<IBlockResult>
    {
        private readonly SignerSink m_signerSink;

        /// <summary>Create a new <see cref="DefaultSignatureCalculator"/>.</summary>
        /// <param name="signer">The signer.</param>
        public DefaultSignatureCalculator(ISigner signer)
        {
            m_signerSink = new SignerSink(signer);
        }

        public Stream Stream => m_signerSink;

        /// <inheritdoc/>
        public IBlockResult GetResult() => new DefaultSignatureResult(m_signerSink.Signer);
    }
}
