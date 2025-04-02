using System;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    /**
    * A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
    * be used to produce cipher text which is the same outLength as the plain text.
    */
    public class CtsBlockCipher
        : BufferedBlockCipher
    {
        private readonly int m_blockSize;

        public CtsBlockCipher(IBlockCipher cipher)
            : this(EcbBlockCipher.GetBlockCipherMode(cipher))
        {
        }

        /**
        * Create a buffered block cipher that uses Cipher Text Stealing
        *
        * @param cipher the underlying block cipher this buffering object wraps.
        */
        public CtsBlockCipher(IBlockCipherMode cipherMode)
        {
            if (!(cipherMode is CbcBlockCipher || cipherMode is EcbBlockCipher))
                throw new ArgumentException("CtsBlockCipher can only accept ECB, or CBC ciphers");

            m_cipherMode = cipherMode;

            m_blockSize = cipherMode.GetBlockSize();

            buf = new byte[m_blockSize * 2];
            bufOff = 0;
        }

        public override int GetBlockSize() => m_blockSize;

        /**
        * return the size of the output buffer required for an update plus a
        * doFinal with an input of length bytes.
        *
        * @param length the outLength of the input.
        * @return the space required to accommodate a call to update and doFinal
        * with length bytes of input.
        */
        public override int GetOutputSize(int length) => bufOff + length;

        /**
        * return the size of the output buffer required for an update of 'length' bytes.
        *
        * @param length the outLength of the input.
        * @return the space required to accommodate a call to update
        * with length bytes of input.
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
                Check.OutputLength(output, outOff, m_blockSize, "output buffer too short");

                resultLen = m_cipherMode.ProcessBlock(buf, 0, output, outOff);
				Debug.Assert(resultLen == m_blockSize);

				Array.Copy(buf, m_blockSize, buf, 0, m_blockSize);
                bufOff = m_blockSize;
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
                Check.OutputLength(output, m_blockSize, "output buffer too short");

                resultLen = m_cipherMode.ProcessBlock(buf, output);
                Debug.Assert(resultLen == m_blockSize);

                Array.Copy(buf, m_blockSize, buf, 0, m_blockSize);
                bufOff = m_blockSize;
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
        * @param length the number of bytes to be copied out of the input array.
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
            int available = buf.Length - bufOff;

            if (length > available)
            {
                int updateOutputSize = GetUpdateOutputSize(length);
                Debug.Assert(updateOutputSize >= m_blockSize);
                Check.OutputLength(output, outOff, updateOutputSize, "output buffer too short");

                Array.Copy(input, inOff, buf, bufOff, available);
                inOff += available;
                length -= available;

                // Handle destructive overlap by copying the remaining input
                if (output == input && SegmentsOverlap(outOff, m_blockSize, inOff, length))
                {
                    input = new byte[length];
                    Array.Copy(output, inOff, input, 0, length);
                    inOff = 0;
                }

                resultLen = m_cipherMode.ProcessBlock(buf, 0, output, outOff);
                Array.Copy(buf, m_blockSize, buf, 0, m_blockSize);
                bufOff = m_blockSize;

                while (length > m_blockSize)
                {
                    resultLen += m_cipherMode.ProcessBlock(buf, 0, output, outOff + resultLen);
                    Array.Copy(input, inOff, buf, 0, m_blockSize);
                    inOff += m_blockSize;
                    length -= m_blockSize;
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
            int available = buf.Length - bufOff;

            if (input.Length > available)
            {
                int updateOutputSize = GetUpdateOutputSize(input.Length);
                Debug.Assert(updateOutputSize >= m_blockSize);
                Check.OutputLength(output, updateOutputSize, "output buffer too short");

                input[..available].CopyTo(buf.AsSpan(bufOff));
                input = input[available..];

                // Handle destructive overlap by copying the remaining input
                if (output[..m_blockSize].Overlaps(input))
                {
                    byte[] tmp = new byte[input.Length];
                    input.CopyTo(tmp);
                    input = tmp;
                }

                resultLen = m_cipherMode.ProcessBlock(buf, output);
                Array.Copy(buf, m_blockSize, buf, 0, m_blockSize);
                bufOff = m_blockSize;

                while (input.Length > m_blockSize)
                {
                    resultLen += m_cipherMode.ProcessBlock(buf, output[resultLen..]);
                    input[..m_blockSize].CopyTo(buf);
                    input = input[m_blockSize..];
                }
            }

            input.CopyTo(buf.AsSpan(bufOff));
            bufOff += input.Length;
            return resultLen;
        }
#endif

        /**
        * Process the last block in the buffer.
        *
        * @param out the array the block currently being held is copied into.
        * @param outOff the offset at which the copying starts.
        * @return the number of output bytes copied to out.
        * @exception DataLengthException if there is insufficient space in out for
        * the output.
        * @exception InvalidOperationException if the underlying cipher is not
        * initialised.
        * @exception InvalidCipherTextException if cipher text decrypts wrongly (in
        * case the exception will never Get thrown).
        */
        public override int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(Spans.FromNullable(output, outOff));
#else
            try
            {
                Check.DataLength(bufOff < m_blockSize, "need at least one block of input for CTS");
                Check.OutputLength(output, outOff, bufOff, "output buffer too short");

                if (forEncryption)
                {
                    m_cipherMode.ProcessBlock(buf, 0, buf, 0);

                    for (int i = bufOff; i < buf.Length; ++i)
                    {
                        buf[i] = buf[i - m_blockSize];
                    }
                    for (int i = m_blockSize; i < bufOff; ++i)
                    {
                        buf[i] ^= buf[i - m_blockSize];
                    }

                    m_cipherMode.UnderlyingCipher.ProcessBlock(buf, m_blockSize, output, outOff);

                    Array.Copy(buf, 0, output, outOff + m_blockSize, bufOff - m_blockSize);
                }
                else
                {
                    m_cipherMode.UnderlyingCipher.ProcessBlock(buf, 0, buf, 0);

                    for (int i = m_blockSize; i < bufOff; ++i)
                    {
                        byte t = buf[i - m_blockSize];
                        buf[i - m_blockSize] = buf[i];
                        buf[i] ^= t;
                    }

                    m_cipherMode.ProcessBlock(buf, 0, output, outOff);
                    Array.Copy(buf, m_blockSize, output, outOff + m_blockSize, bufOff - m_blockSize);
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
                Check.DataLength(bufOff < m_blockSize, "need at least one block of input for CTS");
                Check.OutputLength(output, bufOff, "output buffer too short");

                if (forEncryption)
                {
                    m_cipherMode.ProcessBlock(buf, buf);

                    for (int i = bufOff; i < buf.Length; ++i)
                    {
                        buf[i] = buf[i - m_blockSize];
                    }
                    for (int i = m_blockSize; i < bufOff; ++i)
                    {
                        buf[i] ^= buf[i - m_blockSize];
                    }

                    m_cipherMode.UnderlyingCipher.ProcessBlock(buf.AsSpan(m_blockSize), output);
                    buf.AsSpan(0, bufOff - m_blockSize).CopyTo(output[m_blockSize..]);
                }
                else
                {
                    m_cipherMode.UnderlyingCipher.ProcessBlock(buf, buf);

                    for (int i = m_blockSize; i < bufOff; ++i)
                    {
                        byte t = buf[i - m_blockSize];
                        buf[i - m_blockSize] = buf[i];
                        buf[i] ^= t;
                    }

                    m_cipherMode.ProcessBlock(buf, output);
                    buf.AsSpan(m_blockSize, bufOff - m_blockSize).CopyTo(output[m_blockSize..]);
                }

                return bufOff;
            }
            finally
            {
                Reset();
            }
        }
#endif
    }
}
