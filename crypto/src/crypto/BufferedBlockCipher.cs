using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// A wrapper class that allows block ciphers to be used to process data in a piecemeal fashion.
    /// </summary>
    /// <remarks>
    /// The <see cref="BufferedBlockCipher"/> outputs a block only when the buffer is full and more data is being added, or on a <c>DoFinal</c>.
    /// In the case where the underlying cipher is a stream-oriented mode (like CFB or OFB), the last block may not be a multiple of the block size.
    /// </remarks>
    public class BufferedBlockCipher
        : BufferedCipherBase
    {
        /// <summary>The buffer where data is stored before being processed by the cipher.</summary>
        internal byte[] buf;
        /// <summary>The current position in the buffer.</summary>
        internal int bufOff;
        /// <summary>True if initialised for encryption, false for decryption.</summary>
        internal bool forEncryption;
        /// <summary>The underlying cipher mode we are wrapping.</summary>
        internal IBlockCipherMode m_cipherMode;

        /// <summary>
        /// Constructor for subclasses.
        /// </summary>
        protected BufferedBlockCipher()
        {
        }

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="cipher">The underlying block cipher.</param>
        public BufferedBlockCipher(IBlockCipher cipher)
            : this(EcbBlockCipher.GetBlockCipherMode(cipher))
        {
        }

        /// <summary>
        /// Create a buffered block cipher without padding.
        /// </summary>
        /// <param name="cipherMode">The underlying block cipher mode this buffering object wraps.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="cipherMode"/> is null.</exception>
        /// <exception cref="ArgumentException">If the block size is non-positive.</exception>
        public BufferedBlockCipher(IBlockCipherMode cipherMode)
        {
            if (cipherMode == null)
                throw new ArgumentNullException(nameof(cipherMode));

            int blockSize = cipherMode.GetBlockSize();
            if (blockSize < 1)
                throw new ArgumentException("must have a positive block size", nameof(cipherMode));

            m_cipherMode = cipherMode;
            buf = new byte[blockSize];
            bufOff = 0;
        }

        /// <summary>
        /// The algorithm name for the underlying cipher.
        /// </summary>
        /// <returns>The name of the underlying algorithm.</returns>
        public override string AlgorithmName => m_cipherMode.AlgorithmName;

        /// <summary>
        /// Initialise the cipher.
        /// </summary>
        /// <param name="forEncryption">If true the cipher is initialised for encryption, if false for decryption.</param>
        /// <param name="parameters">The key and other data required by the cipher.</param>
        /// <exception cref="ArgumentException">If the parameters argument is inappropriate.</exception>
        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            parameters = ParameterUtilities.IgnoreRandom(parameters);

            // TODO[api] Redundantly resets the cipher mode
            Reset();

            m_cipherMode.Init(forEncryption, parameters);
        }

        /// <summary>
        /// Return the block size for the underlying cipher.
        /// </summary>
        /// <returns>The block size in bytes.</returns>
        public override int GetBlockSize() => m_cipherMode.GetBlockSize();

        /// <summary>
        /// Return the size of the output buffer required for an update plus a DoFinal with an input of <paramref name="length"/> bytes.
        /// </summary>
        /// <param name="length">The length of the input.</param>
        /// <returns>The space required to accommodate a call to update and DoFinal with <paramref name="length"/> bytes of input.</returns>
        public override int GetOutputSize(int length) => bufOff + length;

        /// <summary>
        /// Return the size of the output buffer required for an update with an input of <paramref name="length"/> bytes.
        /// </summary>
        /// <param name="length">The length of the input.</param>
        /// <returns>The space required to accommodate a call to update with <paramref name="length"/> bytes of input.</returns>
        public override int GetUpdateOutputSize(int length) =>
            GetFullBlocksSize(totalSize: bufOff + length, blockSize: buf.Length);

        /// <summary>
        /// Process a single byte, returning the produced output.
        /// </summary>
        /// <param name="input">The input byte.</param>
        /// <returns>A byte array containing the produced output, or <c>null</c> if no output is produced.</returns>
        public override byte[] ProcessByte(byte input)
        {
            int updateOutputSize = GetUpdateOutputSize(1);

            byte[] output = updateOutputSize > 0 ? new byte[updateOutputSize] : null;

            int outLen = ProcessByte(input, output, 0);

            if (updateOutputSize > 0 && outLen < updateOutputSize)
                return Arrays.CopyOf(output, outLen);

            return output;
        }

        /// <summary>
        /// Process a single byte, producing an output block if necessary.
        /// </summary>
        /// <param name="input">The input byte.</param>
        /// <param name="output">The buffer for any output that might be produced.</param>
        /// <param name="outOff">The offset from which the output will be copied.</param>
        /// <returns>The number of output bytes copied to <paramref name="output"/>.</returns>
        /// <exception cref="DataLengthException">If there isn't enough space in <paramref name="output"/>.</exception>
        /// <exception cref="InvalidOperationException">If the cipher isn't initialised.</exception>
        public override int ProcessByte(byte input, byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessByte(input, Spans.FromNullable(output, outOff));
#else
			buf[bufOff++] = input;

			if (bufOff == buf.Length)
			{
				Check.OutputLength(output, outOff, buf.Length, "output buffer too short");

				bufOff = 0;
				return m_cipherMode.ProcessBlock(buf, 0, output, outOff);
			}

			return 0;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Process a single byte, producing an output block if necessary.
        /// </summary>
        /// <param name="input">The input byte.</param>
        /// <param name="output">The span for any output that might be produced.</param>
        /// <returns>The number of output bytes copied to <paramref name="output"/>.</returns>
        /// <exception cref="DataLengthException">If there isn't enough space in <paramref name="output"/>.</exception>
        /// <exception cref="InvalidOperationException">If the cipher isn't initialised.</exception>
        public override int ProcessByte(byte input, Span<byte> output)
        {
            buf[bufOff++] = input;

            if (bufOff == buf.Length)
            {
                Check.OutputLength(output, buf.Length, "output buffer too short");

                bufOff = 0;
                return m_cipherMode.ProcessBlock(buf, output);
            }

            return 0;
        }
#endif

        /// <summary>
        /// Process an array of bytes, returning the produced output.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">The offset at which the input data starts.</param>
        /// <param name="length">The number of bytes to be processed.</param>
        /// <returns>A byte array containing the produced output, or <c>null</c> if no output is produced.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="input"/> is null.</exception>
        public override byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (length < 1)
                return null;

            int updateOutputSize = GetUpdateOutputSize(length);

            byte[] output = updateOutputSize > 0 ? new byte[updateOutputSize] : null;

            int outLen = ProcessBytes(input, inOff, length, output, 0);

            if (updateOutputSize > 0 && outLen < updateOutputSize)
                return Arrays.CopyOf(output, outLen);

            return output;
        }

        /// <summary>
        /// Process an array of bytes, producing output if necessary.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">The offset at which the input data starts.</param>
        /// <param name="length">The number of bytes to be copied out of the input array.</param>
        /// <param name="output">The buffer for any output that might be produced.</param>
        /// <param name="outOff">The offset from which the output will be copied.</param>
        /// <returns>The number of output bytes copied to <paramref name="output"/>.</returns>
        /// <exception cref="DataLengthException">If there isn't enough space in <paramref name="output"/>.</exception>
        /// <exception cref="InvalidOperationException">If the cipher isn't initialised.</exception>
        public override int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            if (length < 1)
            {
                if (length < 0)
                    throw new ArgumentException("Can't have a negative input length!");

                return 0;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(input.AsSpan(inOff, length), Spans.FromNullable(output, outOff));
#else
			int resultLen = 0;
            int blockSize = buf.Length;
            int available = blockSize - bufOff;

			if (length >= available)
			{
                int updateOutputSize = GetUpdateOutputSize(length);
				Debug.Assert(updateOutputSize >= blockSize);
                Check.OutputLength(output, outOff, updateOutputSize, "output buffer too short");

                Array.Copy(input, inOff, buf, bufOff, available);
                inOff += available;
                length -= available;

                // Handle destructive overlap by copying the remaining input
                if (output == input && Arrays.SegmentsOverlap(outOff, blockSize, inOff, length))
                {
                    input = new byte[length];
                    Array.Copy(output, inOff, input, 0, length);
                    inOff = 0;
                }

                resultLen = m_cipherMode.ProcessBlock(buf, 0, output, outOff);
				bufOff = 0;

				while (length >= blockSize)
				{
					resultLen += m_cipherMode.ProcessBlock(input, inOff, output, outOff + resultLen);
					inOff += blockSize;
					length -= blockSize;
				}
			}

			Array.Copy(input, inOff, buf, bufOff, length);
			bufOff += length;
			return resultLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Process a span of bytes, producing output if necessary.
        /// </summary>
        /// <param name="input">The input span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of output bytes produced.</returns>
        /// <exception cref="DataLengthException">If there isn't enough space in <paramref name="output"/>.</exception>
        /// <exception cref="InvalidOperationException">If the cipher isn't initialised.</exception>
        public override int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int resultLen = 0;
            int blockSize = buf.Length;
            int available = blockSize - bufOff;

            if (input.Length >= available)
            {
                int updateOutputSize = GetUpdateOutputSize(input.Length);
                Debug.Assert(updateOutputSize >= blockSize);
                Check.OutputLength(output, updateOutputSize, "output buffer too short");

                input[..available].CopyTo(buf.AsSpan(bufOff));
                input = input[available..];

                // Handle destructive overlap by copying the remaining input
                if (output[..blockSize].Overlaps(input))
                {
                    byte[] tmp = new byte[input.Length];
                    input.CopyTo(tmp);
                    input = tmp;
                }

                resultLen = m_cipherMode.ProcessBlock(buf, output);
                bufOff = 0;

                while (input.Length >= blockSize)
                {
                    resultLen += m_cipherMode.ProcessBlock(input, output[resultLen..]);
                    input = input[blockSize..];
                }
            }

            input.CopyTo(buf.AsSpan(bufOff));
            bufOff += input.Length;
            return resultLen;
        }
#endif

        /// <summary>
        /// Process any remaining bytes in the buffer, returning the produced output.
        /// </summary>
        /// <returns>A byte array containing the produced output.</returns>
        /// <exception cref="InvalidCipherTextException">If the padding is corrupted.</exception>
        public override byte[] DoFinal()
        {
            int outputSize = GetOutputSize(0);
            if (outputSize < 1)
            {
                Reset();
                return EmptyBuffer;
            }

            byte[] output = new byte[outputSize];

            int outLen = DoFinal(output, 0);
            if (outLen < outputSize)
                return Arrays.CopyOf(output, outLen);

            return output;
        }

        /// <summary>
        /// Process an array of bytes plus any remaining bytes in the buffer, returning the produced output.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">The offset at which the input data starts.</param>
        /// <param name="inLen">The number of bytes to be processed.</param>
        /// <returns>A byte array containing the produced output.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="input"/> is null.</exception>
        /// <exception cref="InvalidCipherTextException">If the padding is corrupted.</exception>
        public override byte[] DoFinal(byte[] input, int inOff, int inLen)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            int outputSize = GetOutputSize(inLen);
            if (outputSize < 1)
            {
                Reset();
                return EmptyBuffer;
            }

            byte[] output = new byte[outputSize];

            int outLen = inLen > 0 ? ProcessBytes(input, inOff, inLen, output, 0) : 0;
            outLen += DoFinal(output, outLen);

            if (outLen < outputSize)
                return Arrays.CopyOf(output, outLen);

            return output;
        }

        /// <summary>
        /// Process the last block in the buffer.
        /// </summary>
        /// <param name="output">The array the block currently being held is copied into.</param>
        /// <param name="outOff">The offset at which the copying starts.</param>
        /// <returns>The number of output bytes copied to <paramref name="output"/>.</returns>
        /// <exception cref="DataLengthException">If there is insufficient space in <paramref name="output"/>, or the input is not block size aligned.</exception>
        /// <exception cref="InvalidOperationException">If the underlying cipher is not initialised.</exception>
        /// <exception cref="InvalidCipherTextException">If padding is expected and not found.</exception>
        public override int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(Spans.FromNullable(output, outOff));
#else
            try
			{
				if (bufOff != 0)
				{
                    Check.DataLength(!m_cipherMode.IsPartialBlockOkay, "data not block size aligned");
                    Check.OutputLength(output, outOff, bufOff, "output buffer too short for DoFinal()");

                    // NB: Can't copy directly, or we may write too much output
                    m_cipherMode.ProcessBlock(buf, 0, buf, 0);
					Array.Copy(buf, 0, output, outOff, bufOff);
				}

				return bufOff;
			}
			finally
			{
				Reset();
			}
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Process any remaining bytes in the buffer, producing output if necessary.
        /// </summary>
        /// <param name="output">The output span.</param>
        /// <returns>The number of output bytes produced.</returns>
        /// <exception cref="DataLengthException">If there isn't enough space in <paramref name="output"/>, or the input is not block size aligned.</exception>
        /// <exception cref="InvalidOperationException">If the underlying cipher is not initialised.</exception>
        /// <exception cref="InvalidCipherTextException">If padding is expected and not found.</exception>
        public override int DoFinal(Span<byte> output)
        {
            try
            {
                if (bufOff != 0)
                {
                    Check.DataLength(!m_cipherMode.IsPartialBlockOkay, "data not block size aligned");
                    Check.OutputLength(output, bufOff, "output buffer too short for DoFinal()");

                    // NB: Can't copy directly, or we may write too much output
                    m_cipherMode.ProcessBlock(buf, buf);
                    buf.AsSpan(0, bufOff).CopyTo(output);
                }

                return bufOff;
            }
            finally
            {
                Reset();
            }
        }
#endif

        /// <summary>
        /// Reset the buffer and cipher.
        /// </summary>
        /// <remarks>
        /// After resetting, the object is in the same state as it was after the last init (if there was one).
        /// </remarks>
        public override void Reset()
        {
            Array.Clear(buf, 0, buf.Length);
            bufOff = 0;

            m_cipherMode.Reset();
        }
    }
}
