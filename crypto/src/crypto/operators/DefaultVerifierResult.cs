using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Operators
{
    // TODO[api] sealed
    public class DefaultVerifierResult
        : IVerifier
    {
        private readonly ISigner m_signer;

        public DefaultVerifierResult(ISigner signer)
        {
            m_signer = signer;
        }

        public bool IsVerified(byte[] signature) => m_signer.VerifySignature(signature);

        // TODO[api] Use ISigner.VerifySignature(ReadOnlySpan<byte>) when available
        public bool IsVerified(byte[] sig, int sigOff, int sigLen) =>
            IsVerified(Arrays.CopyOfRange(sig, sigOff, sigOff + sigLen));
    }
}
