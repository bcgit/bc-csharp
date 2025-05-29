using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /**
	* A wrapper class that allows block ciphers to be used to process data in
	* a piecemeal fashion with padding. The PaddedBufferedBlockCipher
	* outputs a block only when the buffer is full and more data is being added,
	* or on a doFinal (unless the current block in the buffer is a pad block).
	* The default padding mechanism used is the one outlined in Pkcs5/Pkcs7.
	*/
    public class PaddedBufferedBlockCipher
        : BufferedBlockCipher
    {
        private readonly IBlockCipherPadding m_padding;

        public PaddedBufferedBlockCipher(IBlockCipher cipher, IBlockCipherPadding padding)
            : this(EcbBlockCipher.GetBlockCipherMode(cipher), padding)
        {
        }

        /**
		* Create a buffered block cipher with the desired padding.
		*
		* @param cipher the underlying block cipher this buffering object wraps.
		* @param padding the padding type.
		*/
        public PaddedBufferedBlockCipher(IBlockCipherMode cipherMode, IBlockCipherPadding padding)
            : base(cipherMode)
        {
            m_padding = padding;
        }

        /**
		* Create a buffered block cipher Pkcs7 padding
		*
		* @param cipher the underlying block cipher this buffering object wraps.
		*/
        public PaddedBufferedBlockCipher(IBlockCipherMode cipherMode)
            : this(cipherMode, new Pkcs7Padding())
        {
        }

        /**
		* initialise the cipher.
		*
		* @param forEncryption if true the cipher is initialised for
		*  encryption, if false for decryption.
		* @param param the key and other data required by the cipher.
		* @exception ArgumentException if the parameters argument is
		* inappropriate.
		*/
        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            SecureRandom initRandom = null;
            if (parameters is ParametersWithRandom withRandom)
            {
                initRandom = withRandom.Random;
                parameters = withRandom.Parameters;
            }

            // TODO[api] Redundantly resets the cipher mode
            Reset();

            m_padding.Init(initRandom);
            m_cipherMode.Init(forEncryption, parameters);
        }

        /**
		* return the minimum size of the output buffer required for an update
		* plus a doFinal with an input of len bytes.
		*
		* @param len the length of the input.
		* @return the space required to accommodate a call to update and doFinal
		* with len bytes of input.
		*/
        public override int GetOutputSize(int length)
        {
            int totalSize = bufOff + length;
            int blockSize = buf.Length;

            return forEncryption
                ? GetFullBlocksSize(totalSize, blockSize) + blockSize
                : GetFullBlocksSize(totalSize + blockSize - 1, blockSize);
        }

        /**
		* return the size of the output buffer required for an update
		* an input of len bytes.
		*
		* @param len the length of the input.
		* @return the space required to accommodate a call to update
		* with len bytes of input.
		*/
        public override int GetUpdateOutputSize(int length) =>
            GetFullBlocksSize(totalSize: bufOff + length - 1, blockSize: buf.Length);

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
			int resultLen = 0;

			if (bufOff == buf.Length)
			{
                Check.OutputLength(output, outOff, buf.Length, "output buffer too short");

                resultLen = m_cipherMode.ProcessBlock(buf, 0, output, outOff);
				bufOff = 0;
			}

			buf[bufOff++] = input;

			return resultLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int ProcessByte(byte input, Span<byte> output)
        {
            int resultLen = 0;

            if (bufOff == buf.Length)
            {
                Check.OutputLength(output, buf.Length, "output buffer too short");

                resultLen = m_cipherMode.ProcessBlock(buf, output);
                bufOff = 0;
            }

            buf[bufOff++] = input;

            return resultLen;
        }
#endif

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

			if (length > available)
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

				while (length > blockSize)
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

            if (input.Length > available)
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

                while (input.Length > blockSize)
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

        /**
		* Process the last block in the buffer. If the buffer is currently
		* full and padding needs to be added a call to doFinal will produce
		* 2 * GetBlockSize() bytes.
		*
		* @param out the array the block currently being held is copied into.
		* @param outOff the offset at which the copying starts.
		* @return the number of output bytes copied to out.
		* @exception DataLengthException if there is insufficient space in out for
		* the output or we are decrypting and the input is not block size aligned.
		* @exception InvalidOperationException if the underlying cipher is not
		* initialised.
		* @exception InvalidCipherTextException if padding is expected and not found.
		*/
        public override int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(Spans.FromNullable(output, outOff));
#else
			try
			{
                int resultLen = 0;
                int blockSize = buf.Length;

				if (forEncryption)
				{
					if (bufOff == blockSize)
					{
						Check.OutputLength(output, outOff, blockSize * 2, "output buffer too short");

						resultLen = m_cipherMode.ProcessBlock(buf, 0, output, outOff);
						bufOff = 0;
					}
					else
					{
                        Check.OutputLength(output, outOff, blockSize, "output buffer too short");
                    }

                    m_padding.AddPadding(buf, bufOff);

					resultLen += m_cipherMode.ProcessBlock(buf, 0, output, outOff + resultLen);
				}
				else
				{
                    Check.DataLength(bufOff != blockSize, "last block incomplete in decryption");

					resultLen = m_cipherMode.ProcessBlock(buf, 0, buf, 0);
					//bufOff = 0;
					resultLen -= m_padding.PadCount(buf);

					// We only restrict to the actual data, not the GetOutputSize bound
                    Check.OutputLength(output, outOff, resultLen, "output buffer too short");

                    Array.Copy(buf, 0, output, outOff, resultLen);
				}

				return resultLen;
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
                int resultLen = 0;
                int blockSize = buf.Length;

                if (forEncryption)
                {
                    if (bufOff == blockSize)
                    {
                        Check.OutputLength(output, blockSize * 2, "output buffer too short");

                        resultLen = m_cipherMode.ProcessBlock(buf, output);
                        bufOff = 0;
                    }
                    else
                    {
                        Check.OutputLength(output, blockSize, "output buffer too short");
                    }

                    m_padding.AddPadding(buf, bufOff);

                    resultLen += m_cipherMode.ProcessBlock(buf, output[resultLen..]);
                }
                else
                {
                    Check.DataLength(bufOff != blockSize, "last block incomplete in decryption");

                    resultLen = m_cipherMode.ProcessBlock(buf, buf);
                    //bufOff = 0;

                    resultLen -= m_padding.PadCount(buf);

                    // We only restrict to the actual data, not the GetOutputSize bound
                    Check.OutputLength(output, resultLen, "output buffer too short");

                    buf.AsSpan(0, resultLen).CopyTo(output);
                }

                return resultLen;
            }
            finally
            {
                Reset();
            }
        }
#endif
    }
}
