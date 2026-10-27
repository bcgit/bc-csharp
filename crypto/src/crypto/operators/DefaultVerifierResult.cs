using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The result of a signature verification, backed by a signer.</summary>
    // TODO[api] sealed
    public class DefaultVerifierResult
        : IVerifier
    {
        private readonly ISigner m_signer;

        /// <summary>Create a new <see cref="DefaultVerifierResult"/>.</summary>
        /// <param name="signer">The signer.</param>
        public DefaultVerifierResult(ISigner signer)
        {
            m_signer = signer;
        }

        /// <inheritdoc/>
        public bool IsVerified(byte[] signature) => m_signer.VerifySignature(signature);

        /// <inheritdoc/>
        // TODO[api] Use ISigner.VerifySignature(ReadOnlySpan<byte>) when available
        public bool IsVerified(byte[] sig, int sigOff, int sigLen) =>
            IsVerified(Arrays.CopyOfRange(sig, sigOff, sigOff + sigLen));
    }
}
