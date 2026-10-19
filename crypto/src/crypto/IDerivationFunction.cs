using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Base interface for general purpose byte derivation functions.</summary>
    public interface IDerivationFunction
    {
        /// <summary>Initialise the derivation function.</summary>
        /// <param name="parameters">The parameters.</param>
        void Init(IDerivationParameters parameters);

        /// <summary>The message digest used as the basis for the function.</summary>
        IDigest Digest { get; }

        /// <summary>Generate bytes from the derivation function.</summary>
        /// <param name="output">The buffer to receive the bytes.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <param name="length">The number of bytes to generate.</param>
        /// <returns>The number of bytes generated.</returns>
        int GenerateBytes(byte[] output, int outOff, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Generate bytes from the derivation function.</summary>
        /// <param name="output">The buffer to receive the bytes.</param>
        /// <returns>The number of bytes generated.</returns>
        int GenerateBytes(Span<byte> output);
#endif
    }
}
