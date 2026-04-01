using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// A cipher mode that includes authenticated encryption with a streaming mode and optional
    /// associated data.
    /// </summary>
    /// <remarks>
    /// Implementations of this interface may operate in a packet mode (where all input data is
    /// buffered and processed during the call to DoFinal, or in a streaming mode (where output
    /// data is incrementally produced with each call to ProcessByte or ProcessBytes. This is
    /// important to consider during decryption: in a streaming mode, unauthenticated plaintext
    /// data may be output prior to the call to DoFinal that results in an authentication failure.
    /// The higher level protocol utilising this cipher must ensure the plaintext data is handled
    /// appropriately until the end of data is reached and the entire ciphertext is authenticated.
    /// </remarks>
    /// <see cref="AeadParameters"/>
    public interface IAeadCipher
    {
        /// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

        /// <summary>Initialise the cipher.</summary>
        /// <remarks>Parameter can either be an AeadParameters or a ParametersWithIV object.</remarks>
        /// <param name="forEncryption">Initialise for encryption if true, for decryption if false.</param>
        /// <param name="parameters">The key or other data required by the cipher.</param>
        void Init(bool forEncryption, ICipherParameters parameters);

        /// <summary>Add a single byte to the associated data check.</summary>
        /// <remarks>If the implementation supports it, this will be an online operation and will not retain the associated data.</remarks>
        /// <param name="input">The byte to be processed.</param>
        void ProcessAadByte(byte input);

        /// <summary>Add a sequence of bytes to the associated data check.</summary>
        /// <remarks>If the implementation supports it, this will be an online operation and will not retain the associated data.</remarks>
        /// <param name="inBytes">The input byte array.</param>
        /// <param name="inOff">The offset into the input array where the data to be processed starts.</param>
        /// <param name="len">The number of bytes to be processed.</param>
        void ProcessAadBytes(byte[] inBytes, int inOff, int len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Add a span of bytes to the associated data check.</summary>
        /// <remarks>If the implementation supports it, this will be an online operation and will not retain the associated data.</remarks>
        /// <param name="input">the span containing the data.</param>
        void ProcessAadBytes(ReadOnlySpan<byte> input);
#endif

        /// <summary>Process a single byte of data.</summary>
        /// <param name="input">The byte to be processed.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>The number of bytes written to the output buffer.</returns>
        /// <exception cref="DataLengthException">If the output buffer is too small.</exception>
        int ProcessByte(byte input, byte[] outBytes, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a single byte of data using Spans.</summary>
        /// <param name="input">The byte to be processed.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of bytes written to the output span.</returns>
        int ProcessByte(byte input, Span<byte> output);
#endif

        /// <summary>Process a sequence of bytes from the input buffer.</summary>
        /// <param name="inBytes">The input buffer.</param>
        /// <param name="inOff">The offset into the input buffer.</param>
        /// <param name="len">The length of data to process.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>The number of bytes written to the output buffer.</returns>
        /// <exception cref="DataLengthException">If the output buffer is too small.</exception>
        int ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a span of bytes from the input.</summary>
        /// <param name="input">The input span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of bytes written to the output span.</returns>
        int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        /// <summary>Finish the operation, generating or verifying the MAC.</summary>
        /// <param name="outBytes">The output buffer for remaining data and/or MAC.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>Number of bytes written to the output buffer.</returns>
        /// <exception cref="InvalidOperationException">If the cipher is in an inappropriate state.</exception>
        /// <exception cref="InvalidCipherTextException">If the MAC check fails.</exception>
        int DoFinal(byte[] outBytes, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Finish the operation using Spans, generating or verifying the MAC.</summary>
        /// <param name="output">The output span for remaining data and/or MAC.</param>
        /// <returns>Number of bytes written to the output span.</returns>
        /// <exception cref="InvalidCipherTextException">If the MAC check fails.</exception>
        int DoFinal(Span<byte> output);
#endif

        /// <summary>Return the Message Authentication Code (MAC) generated or verified by the cipher.</summary>
        /// <returns>A byte array containing the MAC Block.</returns>
        byte[] GetMac();

        /// <summary>Return the size of the output buffer required for a ProcessBytes call with <paramref name="len"/> bytes.</summary>
        /// <param name="len">Input length.</param>
        /// <returns>The space required for ProcessBytes with len bytes of input.</returns>
        int GetUpdateOutputSize(int len);

        /// <summary>Return the size of the output buffer required for a ProcessBytes plus a DoFinal call with <paramref name="len"/> bytes.</summary>
        /// <param name="len">Input length.</param>
        /// <returns>The space required for ProcessBytes and DoFinal with len bytes of input.</returns>
        int GetOutputSize(int len);

        /// <summary>
        /// Reset the cipher to the same state as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
