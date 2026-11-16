using System;
using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>
    /// The default verifier calculator, which feeds the data written to it into a signer in verification mode.
    /// </summary>
    // TODO[api] sealed
    public class DefaultVerifierCalculator
        : IStreamCalculator<IVerifier>
    {
        private readonly SignerSink m_signerSink;

        /// <summary>Create a new <see cref="DefaultVerifierCalculator"/>.</summary>
        /// <param name="signer">The signer.</param>
        public DefaultVerifierCalculator(ISigner signer)
        {
            m_signerSink = new SignerSink(signer);
        }

        /// <summary>Gets the underlying stream.</summary>
        public Stream Stream => m_signerSink;

        /// <inheritdoc/>
        public IVerifier GetResult() => new DefaultVerifierResult(m_signerSink.Signer);
    }
}
