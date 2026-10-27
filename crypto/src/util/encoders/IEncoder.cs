using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    /**
     * Encode and decode byte arrays (typically from binary to 7-bit ASCII
     * encodings).
     */
    public interface IEncoder
    {
        /// <summary>Encode data to a stream.</summary>
        /// <param name="data">The data to encode.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the data starts.</param>
        /// <param name="length">The number of bytes to encode.</param>
        /// <param name="outStream">The stream to write to.</param>
        /// <returns>The number of bytes written.</returns>
        int Encode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Encode data to a stream.</summary>
        /// <param name="data">The data to encode.</param>
        /// <param name="outStream">The stream to write to.</param>
        /// <returns>The number of bytes written.</returns>
        int Encode(ReadOnlySpan<byte> data, Stream outStream);
#endif

        /// <summary>Decode data to a stream.</summary>
        /// <param name="data">The data to decode.</param>
        /// <param name="off">The offset into <paramref name="data"/> at which the data starts.</param>
        /// <param name="length">The number of bytes to decode.</param>
        /// <param name="outStream">The stream to write to.</param>
        /// <returns>The number of bytes written.</returns>
        int Decode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Decode data to a stream.</summary>
        /// <param name="data">The data to decode.</param>
        /// <param name="outStream">The stream to write to.</param>
        /// <returns>The number of bytes written.</returns>
        int Decode(ReadOnlySpan<byte> data, Stream outStream);
#endif

        /// <summary>Decode encoded data given as a string, to a stream.</summary>
        /// <param name="data">The string to decode.</param>
        /// <param name="outStream">The stream to write to.</param>
        /// <returns>The number of bytes written.</returns>
        int DecodeString(string data, Stream outStream);
    }
}
