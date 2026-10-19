using System;

namespace Org.BouncyCastle.Utilities.Encoders
{
    /// <summary>
    /// Translator interface.
    /// </summary>
    public interface ITranslator
    {
        /// <summary>Return the encoded block size.</summary>
        int GetEncodedBlockSize();

        /// <summary>Encode a block of data.</summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes to encode.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into <paramref name="outBytes"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int Encode(byte[] input, int inOff, int length, byte[] outBytes, int outOff);

        /// <summary>Return the decoded block size.</summary>
        int GetDecodedBlockSize();

        /// <summary>Decode a block of data.</summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes to decode.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into <paramref name="outBytes"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int Decode(byte[] input, int inOff, int length, byte[] outBytes, int outOff);
    }

}
