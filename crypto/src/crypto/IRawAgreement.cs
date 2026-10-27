using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for key agreement functions that operate on raw (unencoded) key parameters.</summary>
    public interface IRawAgreement
    {
        /// <summary>Initialise the agreement with the private key of this party.</summary>
        /// <param name="parameters">The private key parameters.</param>
        void Init(ICipherParameters parameters);

        /// <summary>Gets the agreement size.</summary>
        int AgreementSize { get; }

        /// <summary>Calculate the agreement value with the public key of the other party.</summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="buf">The buffer to receive the agreement value.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Calculate the agreement value with the public key of the other party.</summary>
        /// <param name="publicKey">The public key of the other party.</param>
        /// <param name="output">The buffer to receive the agreement value.</param>
        void CalculateAgreement(ICipherParameters publicKey, Span<byte> output);
#endif
    }
}
