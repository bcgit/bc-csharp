using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The default MAC calculator, which feeds the data written to it into a MAC.</summary>
    public sealed class DefaultMacCalculator
        : IStreamCalculator<IBlockResult>
    {
        private readonly MacSink m_macSink;

        /// <summary>Create a new <see cref="DefaultMacCalculator"/>.</summary>
        /// <param name="mac">The MAC.</param>
        public DefaultMacCalculator(IMac mac)
        {
            m_macSink = new MacSink(mac);
        }

        public Stream Stream => m_macSink;

        /// <inheritdoc/>
        public IBlockResult GetResult() => new DefaultMacResult(m_macSink.Mac);
    }
}
