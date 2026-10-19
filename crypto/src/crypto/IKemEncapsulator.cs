using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for key encapsulation mechanism (KEM) encapsulators.</summary>
    public interface IKemEncapsulator
    {
        /// <summary>Initialise the encapsulator.</summary>
        /// <param name="parameters">The public key (and optionally other parameters).</param>
        void Init(ICipherParameters parameters);

        /// <summary>Gets the encapsulation length.</summary>
        int EncapsulationLength { get; }

        /// <summary>Gets the secret length.</summary>
        int SecretLength { get; }

        /// <summary>Generate a shared secret together with its encapsulation.</summary>
        /// <param name="encBuf">The buffer to receive the encapsulation.</param>
        /// <param name="encOff">The offset into <paramref name="encBuf"/> at which to start writing.</param>
        /// <param name="encLen">The length of the encapsulation.</param>
        /// <param name="secBuf">The buffer to receive the secret.</param>
        /// <param name="secOff">The offset into <paramref name="secBuf"/> at which to start writing.</param>
        /// <param name="secLen">The length of the secret.</param>
        void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Generate a shared secret together with its encapsulation.</summary>
        /// <param name="encapsulation">The buffer to receive the encapsulation.</param>
        /// <param name="secret">The buffer to receive the secret.</param>
        void Encapsulate(Span<byte> encapsulation, Span<byte> secret);
#endif
    }
}
