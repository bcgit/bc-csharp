using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /**
	* A wrapper class that allows block ciphers to be used to process data in
	* a piecemeal fashion. The BufferedBlockCipher outputs a block only when the
	* buffer is full and more data is being added, or on a doFinal.
	* <p>
	* Note: in the case where the underlying cipher is either a CFB cipher or an
	* OFB one the last block may not be a multiple of the block size.
	* </p>
	*/
    public class BufferedBlockCipher
        : BufferedCipherBase
    {
        internal byte[] buf;
        internal int bufOff;
        internal bool forEncryption;
        internal IBlockCipherMode m_cipherMode;

        /**
		* constructor for subclasses
		*/
        protected BufferedBlockCipher()
        {
        }

        public BufferedBlockCipher(IBlockCipher cipher)
            : this(EcbBlockCipher.GetBlockCipherMode(cipher))
        {
        }

        /**
		* Create a buffered block cipher without padding.
		*
		* @param cipher the underlying block cipher this buffering object wraps.
		* false otherwise.
		*/
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

        public override string AlgorithmName => m_cipherMode.AlgorithmName;

        /**
		* initialise the cipher.
		*
		* @param forEncryption if true the cipher is initialised for
		*  encryption, if false for decryption.
		* @param param the key and other data required by the cipher.
		* @exception ArgumentException if the parameters argument is
		* inappropriate.
		*/
        // Note: This doubles as the Init in the event that this cipher is being used as an IWrapper
        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            parameters = ParameterUtilities.IgnoreRandom(parameters);

            // TODO[api] Redundantly resets the cipher mode
            Reset();

            m_cipherMode.Init(forEncryption, parameters);
        }

        /**
		* return the blocksize for the underlying cipher.
		*
		* @return the blocksize for the underlying cipher.
		*/
        public override int GetBlockSize() => m_cipherMode.GetBlockSize();

        /**
		* return the size of the output buffer required for an update plus a
		* doFinal with an input of len bytes.
		*
		* @param len the length of the input.
		* @return the space required to accommodate a call to update and doFinal
		* with len bytes of input.
		*/
        // Note: Can assume IsPartialBlockOkay is true for purposes of this calculation
        public override int GetOutputSize(int length) => bufOff + length;

        /**
		* return the size of the output buffer required for an update
		* an input of len bytes.
		*
		* @param len the length of the input.
		* @return the space required to accommodate a call to update
		* with len bytes of input.
		*/
        public override int GetUpdateOutputSize(int length) =>
            GetFullBlocksSize(totalSize: bufOff + length, blockSize: buf.Length);

        public override byte[] ProcessByte(byte input)
        {
            int updateOutputSize = GetUpdateOutputSize(1);

            byte[] output = updateOutputSize > 0 ? new byte[updateOutputSize] : null;

            int outLen = ProcessByte(input, output, 0);

            if (updateOutputSize > 0 && outLen < updateOutputSize)
                return Arrays.CopyOf(output, outLen);

            return output;
        }

        /**
		* process a single byte, producing an output block if necessary.
		*
		* @param in the input byte.
		* @param out the space for any output that might be produced.
		* @param outOff the offset from which the output will be copied.
		* @return the number of output bytes copied to out.
		* @exception DataLengthException if there isn't enough space in out.
		* @exception InvalidOperationException if the cipher isn't initialised.
		*/
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

        /**
		* process an array of bytes, producing output if necessary.
		*
		* @param in the input byte array.
		* @param inOff the offset at which the input data starts.
		* @param len the number of bytes to be copied out of the input array.
		* @param out the space for any output that might be produced.
		* @param outOff the offset from which the output will be copied.
		* @return the number of output bytes copied to out.
		* @exception DataLengthException if there isn't enough space in out.
		* @exception InvalidOperationException if the cipher isn't initialised.
		*/
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
                if (output == input && SegmentsOverlap(outOff, blockSize, inOff, length))
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

        /**
		* Process the last block in the buffer.
		*
		* @param out the array the block currently being held is copied into.
		* @param outOff the offset at which the copying starts.
		* @return the number of output bytes copied to out.
		* @exception DataLengthException if there is insufficient space in out for
		* the output, or the input is not block size aligned and should be.
		* @exception InvalidOperationException if the underlying cipher is not
		* initialised.
		* @exception InvalidCipherTextException if padding is expected and not found.
		* @exception DataLengthException if the input is not block size
		* aligned.
		*/
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

        /**
		* Reset the buffer and cipher. After resetting the object is in the same
		* state as it was after the last init (if there was one).
		*/
        public override void Reset()
        {
            Array.Clear(buf, 0, buf.Length);
            bufOff = 0;

            m_cipherMode.Reset();
        }
    }
}
