using System;

namespace Org.BouncyCastle.Crypto
{
    /// <remarks>Block cipher engines are expected to conform to this interface.</remarks>
    public interface IBufferedCipher
    {
        /// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

        /// <summary>Initialise the cipher.</summary>
        /// <param name="forEncryption">If true the cipher is initialised for encryption,
        /// if false for decryption.</param>
        /// <param name="parameters">The key and other data required by the cipher.</param>
        void Init(bool forEncryption, ICipherParameters parameters);

        /// <summary>Return the block size.</summary>
        int GetBlockSize();

        /// <summary>
        /// Get the size of the output for a given amount of input, taking buffered data into account.
        /// </summary>
        /// <param name="inputLen">The length of the input.</param>
        /// <returns>The maximum size of the output of the next <c>ProcessBytes</c> or <c>DoFinal</c> call.</returns>
        int GetOutputSize(int inputLen);

        /// <summary>Get the size of the output of a <c>ProcessBytes</c> call for a given amount of input.</summary>
        /// <param name="inputLen">The length of the input.</param>
        /// <returns>The maximum size of the output.</returns>
        int GetUpdateOutputSize(int inputLen);

        /// <summary>Process a single byte.</summary>
        /// <param name="input">The byte.</param>
        /// <returns>The output produced, or null if there is none.</returns>
        byte[] ProcessByte(byte input);
        /// <summary>Process a single byte, writing any output to a buffer.</summary>
        /// <param name="input">The byte.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int ProcessByte(byte input, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a single byte, writing any output to a buffer.</summary>
        /// <param name="input">The byte.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <returns>The number of bytes written.</returns>
        int ProcessByte(byte input, Span<byte> output);
#endif

        /// <summary>Process a block of bytes.</summary>
        /// <param name="input">The input data.</param>
        /// <returns>The output produced, or null if there is none.</returns>
        byte[] ProcessBytes(byte[] input);
        /// <summary>Process a block of bytes.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes of input.</param>
        /// <returns>The output produced, or null if there is none.</returns>
        byte[] ProcessBytes(byte[] input, int inOff, int length);
        /// <summary>Process a block of bytes, writing any output to a buffer.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int ProcessBytes(byte[] input, byte[] output, int outOff);
        /// <summary>Process a block of bytes, writing any output to a buffer.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes of input.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a block of bytes, writing any output to a buffer.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <returns>The number of bytes written.</returns>
        // TODO[api]
        //byte[] ProcessBytes(ReadOnlySpan<byte> input);
        int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        /// <summary>Finish the operation, optionally processing a last block of input.</summary>
        /// <returns>The final output.</returns>
        byte[] DoFinal();
        /// <summary>Finish the operation, optionally processing a last block of input.</summary>
        /// <param name="input">The input data.</param>
        /// <returns>The final output.</returns>
        byte[] DoFinal(byte[] input);
        /// <summary>Finish the operation, optionally processing a last block of input.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes of input.</param>
        /// <returns>The final output.</returns>
        byte[] DoFinal(byte[] input, int inOff, int length);
        /// <summary>
        /// Finish the operation, writing the final output to a buffer, optionally after processing a last block of
        /// input.
        /// </summary>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(byte[] output, int outOff);
        /// <summary>
        /// Finish the operation, writing the final output to a buffer, optionally after processing a last block of
        /// input.
        /// </summary>
        /// <param name="input">The input data.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(byte[] input, byte[] output, int outOff);
        /// <summary>
        /// Finish the operation, writing the final output to a buffer, optionally after processing a last block of
        /// input.
        /// </summary>
        /// <param name="input">The input data.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the data starts.</param>
        /// <param name="length">The number of bytes of input.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <param name="outOff">The offset into <paramref name="output"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Finish the operation, writing the final output to a buffer, optionally after processing a last block of
        /// input.
        /// </summary>
        /// <param name="output">The buffer to receive the output.</param>
        /// <returns>The number of bytes written.</returns>
        // TODO[api]
        //byte[] DoFinal(ReadOnlySpan<byte> input);
        int DoFinal(Span<byte> output);
        /// <summary>
        /// Finish the operation, writing the final output to a buffer, optionally after processing a last block of
        /// input.
        /// </summary>
        /// <param name="input">The input data.</param>
        /// <param name="output">The buffer to receive the output.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        /// <summary>
        /// Reset the cipher. After resetting the cipher is in the same state
        /// as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
