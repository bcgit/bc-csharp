using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for key encapsulation mechanism (KEM) decapsulators.</summary>
    public interface IKemDecapsulator
    {
        /// <summary>Initialise the decapsulator.</summary>
        /// <param name="parameters">The private key (and optionally other parameters).</param>
        void Init(ICipherParameters parameters);

        int EncapsulationLength { get; }

        int SecretLength { get; }

        /// <summary>Recover the shared secret from an encapsulation.</summary>
        /// <param name="encBuf">The buffer holding the encapsulation.</param>
        /// <param name="encOff">The offset into <paramref name="encBuf"/> at which the encapsulation starts.</param>
        /// <param name="encLen">The length of the encapsulation.</param>
        /// <param name="secBuf">The buffer to receive the secret.</param>
        /// <param name="secOff">The offset into <paramref name="secBuf"/> at which to start writing.</param>
        /// <param name="secLen">The length of the secret.</param>
        void Decapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Recover the shared secret from an encapsulation.</summary>
        /// <param name="encapsulation">The encapsulation.</param>
        /// <param name="secret">The buffer to receive the secret.</param>
        void Decapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> secret);
#endif
    }
}
