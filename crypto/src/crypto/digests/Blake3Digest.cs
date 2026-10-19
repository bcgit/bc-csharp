using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>
    /// Implementation of the BLAKE3 hash function, supporting plain hashing, keyed hashing, key derivation and
    /// extendable output.
    /// </summary>
    public sealed class Blake3Digest
        : IDigest, IMemoable, IXof
    {
        /**
         * Already outputting error.
         */
        private const string ERR_OUTPUTTING = "Already outputting";

        /**
         * Number of Words.
         */
        private const int NUMWORDS = 8;

        /**
         * Number of Rounds.
         */
        private const int ROUNDS = 7;

        /**
         * Buffer length.
         */
        private const int BLOCKLEN = NUMWORDS * Integers.NumBytes * 2;

        /**
         * Chunk length.
         */
        private const int CHUNKLEN = 1024;

        /**
         * ChunkStart Flag.
         */
        private const int CHUNKSTART = 1;

        /**
         * ChunkEnd Flag.
         */
        private const int CHUNKEND = 2;

        /**
         * Parent Flag.
         */
        private const int PARENT = 4;

        /**
         * Root Flag.
         */
        private const int ROOT = 8;

        /**
         * KeyedHash Flag.
         */
        private const int KEYEDHASH = 16;

        /**
         * DeriveContext Flag.
         */
        private const int DERIVECONTEXT = 32;

        /**
         * DeriveKey Flag.
         */
        private const int DERIVEKEY = 64;

        /**
         * Chaining0 State Locations.
         */
        private const int CHAINING0 = 0;

        /**
         * Chaining1 State Location.
         */
        private const int CHAINING1 = 1;

        /**
         * Chaining2 State Location.
         */
        private const int CHAINING2 = 2;

        /**
         * Chaining3 State Location.
         */
        private const int CHAINING3 = 3;

        /**
         * Chaining4 State Location.
         */
        private const int CHAINING4 = 4;

        /**
         * Chaining5 State Location.
         */
        private const int CHAINING5 = 5;

        /**
         * Chaining6 State Location.
         */
        private const int CHAINING6 = 6;

        /**
         * Chaining7 State Location.
         */
        private const int CHAINING7 = 7;

        /**
         * IV0 State Locations.
         */
        private const int IV0 = 8;

        /**
         * IV1 State Location.
         */
        private const int IV1 = 9;

        /**
         * IV2 State Location.
         */
        private const int IV2 = 10;

        /**
         * IV3 State Location.
         */
        private const int IV3 = 11;

        /**
         * Count0 State Location.
         */
        private const int COUNT0 = 12;

        /**
         * Count1 State Location.
         */
        private const int COUNT1 = 13;

        /**
         * DataLen State Location.
         */
        private const int DATALEN = 14;

        /**
         * Flags State Location.
         */
        private const int FLAGS = 15;

        /**
         * Blake3 Initialization Vector.
         */
        private static readonly uint[] IV = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        /**
         * The byte input/output buffer.
         */
        private readonly byte[] m_theBuffer = new byte[BLOCKLEN];

        /**
         * The key.
         */
        private readonly uint[] m_theK = new uint[NUMWORDS];

        /**
         * The chaining value.
         */
        private readonly uint[] m_theChaining = new uint[NUMWORDS];

        /**
         * The state.
         */
        private readonly uint[] m_theV = new uint[NUMWORDS << 1];

        /**
         * The message Buffer.
         */
        private readonly uint[] m_theM = new uint[NUMWORDS << 1];

        /**
         * The chainingStack.
         */
        private readonly List<uint[]> m_theStack = new List<uint[]>();

        /**
         * The default digestLength.
         */
        private readonly int m_theDigestLen;

        /**
         * Are we outputting?
         */
        private bool m_outputting;

        /**
         * How many more bytes can we output?
         */
        private long m_outputAvailable;

        /**
         * The current mode.
         */
        private int m_theMode;

        /**
         * The output mode.
         */
        private int m_theOutputMode;

        /**
         * The output dataLen.
         */
        private int m_theOutputDataLen;

        /**
         * The block counter.
         */
        private long m_theCounter;

        /**
         * The # of bytes in the current block.
         */
        private int m_theCurrBytes;

        /**
         * The position of the next byte in the buffer.
         */
        private int m_thePos;

        /// <summary>Create a new <see cref="Blake3Digest"/>.</summary>
        public Blake3Digest()
            : this((BLOCKLEN >> 1) * 8)
        {
        }

        /// <param name="pDigestSize">the default digest size (in bits)</param>
        public Blake3Digest(int pDigestSize)
        {
            m_theDigestLen = pDigestSize / 8;

            Init(null);
        }

        /**
         * Constructor.
         *
         * @param pSource the source digest.
         */
        public Blake3Digest(Blake3Digest pSource)
        {
            /* Copy default digest length */
            m_theDigestLen = pSource.m_theDigestLen;

            /* Initialise from source */
            Reset(pSource);
        }

        /// <inheritdoc/>
        public int GetByteLength() => BLOCKLEN;

        /// <inheritdoc/>
        public string AlgorithmName => "BLAKE3";

        /// <inheritdoc/>
        public int GetDigestSize() => m_theDigestLen;

        /**
         * Initialise.
         *
         * @param pParams the parameters.
         */
        public void Init(Blake3Parameters pParams)
        {
            /* Access key/context */
            byte[] myKey = pParams?.GetKey();
            byte[] myContext = pParams?.GetContext();

            /* Reset the digest */
            Reset();

            /* If we have a key  */
            if (myKey != null)
            {
                /* Initialise with the key */
                InitKey(myKey);
                Arrays.Fill(myKey, 0);

                /* else if we have a context */
            }
            else if (myContext != null)
            {
                /* Initialise for deriving context */
                InitNullKey();
                m_theMode = DERIVECONTEXT;

                /* Derive key from context */
                BlockUpdate(myContext, 0, myContext.Length);
                DoFinal(m_theBuffer, 0);
                InitKeyFromContext();
                Reset();

                /* Else init null key and reset mode */
            }
            else
            {
                InitNullKey();
                m_theMode = 0;
            }
        }

        /// <inheritdoc/>
        public void Update(byte b)
        {
            /* Check that we are not outputting */
            if (m_outputting)
                throw new InvalidOperationException(ERR_OUTPUTTING);

            /* If the buffer is full */
            int blockLen = m_theBuffer.Length;
            int remainingLength = blockLen - m_thePos;
            if (remainingLength == 0)
            {
                /* Process the buffer */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                CompressBlock(m_theBuffer);
#else
                CompressBlock(m_theBuffer, 0);
#endif

                /* Reset the buffer */
                Arrays.Fill(m_theBuffer, 0);
                m_thePos = 0;
            }

            /* Store the byte */
            m_theBuffer[m_thePos] = b;
            m_thePos++;
        }

        /// <inheritdoc/>
        public void BlockUpdate(byte[] pMessage, int pOffset, int pLen)
        {
            /* Ignore null operation */
            if (pMessage == null)
                return;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(pMessage.AsSpan(pOffset, pLen));
#else
            if (pLen == 0)
                return;

            /* Check that we are not outputting */
            if (m_outputting)
                throw new InvalidOperationException(ERR_OUTPUTTING);

            /* Process any bytes currently in the buffer */
            int remainingLen = 0; // left bytes of buffer
            if (m_thePos != 0)
            {
                /* Calculate space remaining in the buffer */
                remainingLen = BLOCKLEN - m_thePos;

                /* If there is sufficient space in the buffer */
                if (remainingLen >= pLen)
                {
                    /* Copy data into buffer and return */
                    Array.Copy(pMessage, pOffset, m_theBuffer, m_thePos, pLen);
                    m_thePos += pLen;
                    return;
                }

                /* Fill the buffer */
                Array.Copy(pMessage, pOffset, m_theBuffer, m_thePos, remainingLen);

                /* Process the buffer */
                CompressBlock(m_theBuffer, 0);

                /* Reset the buffer */
                m_thePos = 0;
                Arrays.Fill(m_theBuffer, 0);
            }

            /* process all blocks except the last one */
            int messagePos;
            int blockWiseLastPos = pOffset + pLen - BLOCKLEN;
            for (messagePos = pOffset + remainingLen; messagePos < blockWiseLastPos; messagePos += BLOCKLEN)
            {
                /* Process the buffer */
                CompressBlock(pMessage, messagePos);
            }

            /* Fill the buffer with the remaining bytes of the message */
            int len = pLen - messagePos;
            Array.Copy(pMessage, messagePos, m_theBuffer, 0, pOffset + len);
            m_thePos += pOffset + len;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (input.IsEmpty)
                return;

            /* Check that we are not outputting */
            if (m_outputting)
                throw new InvalidOperationException(ERR_OUTPUTTING);

            int pLen = input.Length;

            /* Process any bytes currently in the buffer */
            int remainingLen = 0; // left bytes of buffer
            if (m_thePos != 0)
            {
                /* Calculate space remaining in the buffer */
                remainingLen = BLOCKLEN - m_thePos;

                /* If there is sufficient space in the buffer */
                if (remainingLen >= pLen)
                {
                    /* Copy data into buffer and return */
                    input.CopyTo(m_theBuffer.AsSpan(m_thePos));
                    m_thePos += pLen;
                    return;
                }

                /* Fill the buffer */
                input[..remainingLen].CopyTo(m_theBuffer.AsSpan(m_thePos));

                /* Process the buffer */
                CompressBlock(m_theBuffer);

                /* Reset the buffer */
                m_thePos = 0;
                Arrays.Fill(m_theBuffer, 0);
            }

            /* process all blocks except the last one */
            int messagePos;
            int blockWiseLastPos = pLen - BLOCKLEN;
            for (messagePos = remainingLen; messagePos < blockWiseLastPos; messagePos += BLOCKLEN)
            {
                /* Process the buffer */
                CompressBlock(input[messagePos..]);
            }

            /* Fill the buffer with the remaining bytes of the message */
            input[messagePos..].CopyTo(m_theBuffer);
            m_thePos += pLen - messagePos;
        }
#endif

        /// <inheritdoc/>
        public int DoFinal(byte[] pOutput, int pOutOffset)
        {
            return OutputFinal(pOutput, pOutOffset, GetDigestSize());
        }

        /// <inheritdoc/>
        public int OutputFinal(byte[] pOut, int pOutOffset, int pOutLen)
        {
            int length = Output(pOut, pOutOffset, pOutLen);
            Reset();
            return length;
        }

        /// <inheritdoc/>
        public int Output(byte[] pOut, int pOutOffset, int pOutLen)
        {
            Check.OutputLength(pOut, pOutOffset, pOutLen, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Output(pOut.AsSpan(pOutOffset, pOutLen));
#else
            /* If we have not started outputting yet */
            if (!m_outputting)
            {
                /* Process the buffer */
                CompressFinalBlock(m_thePos);
            }

            /* Reject if there is insufficient Xof remaining */
            if (pOutLen < 0 || (m_outputAvailable >= 0 && pOutLen > m_outputAvailable))
                throw new ArgumentException("Insufficient bytes remaining");

            /* If we have some remaining data in the current buffer */
            int dataLeft = pOutLen;
            int outPos = pOutOffset;
            if (m_thePos < BLOCKLEN)
            {
                /* Copy data from current hash */
                int dataToCopy = System.Math.Min(dataLeft, BLOCKLEN - m_thePos);
                Array.Copy(m_theBuffer, m_thePos, pOut, outPos, dataToCopy);

                /* Adjust counters */
                m_thePos += dataToCopy;
                outPos += dataToCopy;
                dataLeft -= dataToCopy;
            }

            /* Loop until we have completed the request */
            while (dataLeft > 0)
            {
                /* Calculate the next block */
                NextOutputBlock();

                /* Copy data from current hash */
                int dataToCopy = System.Math.Min(dataLeft, BLOCKLEN);
                Array.Copy(m_theBuffer, 0, pOut, outPos, dataToCopy);

                /* Adjust counters */
                m_thePos += dataToCopy;
                outPos += dataToCopy;
                dataLeft -= dataToCopy;
            }

            /* Adjust outputAvailable */
            m_outputAvailable -= pOutLen;

            /* Return the number of bytes transferred */
            return pOutLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int DoFinal(Span<byte> output)
        {
            int digestSize = GetDigestSize();
            Check.OutputLength(output, digestSize, "output buffer too short");
            return OutputFinal(output[..digestSize]);
        }

        /// <inheritdoc/>
        public int OutputFinal(Span<byte> output)
        {
            int length = Output(output);
            Reset();
            return length;
        }

        /// <inheritdoc/>
        public int Output(Span<byte> output)
        {
            /* If we have not started outputting yet */
            if (!m_outputting)
            {
                /* Process the buffer */
                CompressFinalBlock(m_thePos);
            }

            int pOutOffset = 0, pOutLen = output.Length;
            /* Reject if there is insufficient Xof remaining */
            if (pOutLen < 0 || (m_outputAvailable >= 0 && pOutLen > m_outputAvailable))
                throw new ArgumentException("Insufficient bytes remaining");

            /* If we have some remaining data in the current buffer */
            int dataLeft = pOutLen;
            int outPos = pOutOffset;
            if (m_thePos < BLOCKLEN)
            {
                /* Copy data from current hash */
                int dataToCopy = System.Math.Min(dataLeft, BLOCKLEN - m_thePos);
                m_theBuffer.AsSpan(m_thePos, dataToCopy).CopyTo(output[outPos..]);

                /* Adjust counters */
                m_thePos += dataToCopy;
                outPos += dataToCopy;
                dataLeft -= dataToCopy;
            }

            /* Loop until we have completed the request */
            while (dataLeft > 0)
            {
                /* Calculate the next block */
                NextOutputBlock();

                /* Copy data from current hash */
                int dataToCopy = System.Math.Min(dataLeft, BLOCKLEN);
                m_theBuffer.AsSpan(0, dataToCopy).CopyTo(output[outPos..]);

                /* Adjust counters */
                m_thePos += dataToCopy;
                outPos += dataToCopy;
                dataLeft -= dataToCopy;
            }

            /* Adjust outputAvailable */
            m_outputAvailable -= pOutLen;

            /* Return the number of bytes transferred */
            return pOutLen;
        }
#endif

        /// <inheritdoc/>
        public void Reset()
        {
            ResetBlockCount();
            m_thePos = 0;
            m_outputting = false;
            Arrays.Fill(m_theBuffer, 0);
        }

        /// <inheritdoc/>
        public void Reset(IMemoable pSource)
        {
            /* Access source */
            Blake3Digest mySource = (Blake3Digest)pSource;

            /*  Reset counter */
            m_theCounter = mySource.m_theCounter;
            m_theCurrBytes = mySource.m_theCurrBytes;
            m_theMode = mySource.m_theMode;

            /* Reset output state */
            m_outputting = mySource.m_outputting;
            m_outputAvailable = mySource.m_outputAvailable;
            m_theOutputMode = mySource.m_theOutputMode;
            m_theOutputDataLen = mySource.m_theOutputDataLen;

            /* Copy state */
            Array.Copy(mySource.m_theChaining, 0, m_theChaining, 0, m_theChaining.Length);
            Array.Copy(mySource.m_theK, 0, m_theK, 0, m_theK.Length);
            Array.Copy(mySource.m_theM, 0, m_theM, 0, m_theM.Length);

            /* Copy stack */
            m_theStack.Clear();
            foreach (var element in mySource.m_theStack)
            {
                m_theStack.Add(Arrays.Clone(element));
            }

            /* Copy buffer */
            Array.Copy(mySource.m_theBuffer, 0, m_theBuffer, 0, m_theBuffer.Length);
            m_thePos = mySource.m_thePos;
        }

        /// <inheritdoc/>
        public IMemoable Copy()
        {
            return new Blake3Digest(this);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void CompressBlock(ReadOnlySpan<byte> block)
        {
            /* Initialise state and compress message */
            InitChunkBlock(BLOCKLEN, false);
            InitM(block);
            Compress();

            /* Adjust stack if we have completed a block */
            if (m_theCurrBytes == 0)
            {
                AdjustStack();
            }
        }

        private void InitM(ReadOnlySpan<byte> block)
        {
            /* Copy message bytes into word array */
            Pack.LE_To_UInt32(block, m_theM);
        }
#else
        /**
         * Compress next block of the message.
         *
         * @param pMessage the message buffer
         * @param pMsgPos  the position within the message buffer
         */
        private void CompressBlock(byte[] pMessage, int pMsgPos)
        {
            /* Initialise state and compress message */
            InitChunkBlock(BLOCKLEN, false);
            InitM(pMessage, pMsgPos);
            Compress();

            /* Adjust stack if we have completed a block */
            if (m_theCurrBytes == 0)
            {
                AdjustStack();
            }
        }

        /**
         * Initialise M from message.
         *
         * @param pMessage the source message
         * @param pMsgPos  the message position
         */
        private void InitM(byte[] pMessage, int pMsgPos)
        {
            /* Copy message bytes into word array */
            Pack.LE_To_UInt32(pMessage, pMsgPos, m_theM);
        }
#endif

        /**
         * Adjust the stack.
         */
        private void AdjustStack()
        {
            /* Loop to combine blocks */
            long myCount = m_theCounter;
            while (myCount > 0)
            {
                /* Break loop if we are not combining */
                if ((myCount & 1) == 1)
                    break;

                /* Build the message to be hashed */
                uint[] myLeft = m_theStack[m_theStack.Count - 1];
                m_theStack.RemoveAt(m_theStack.Count - 1);

                Array.Copy(myLeft, 0, m_theM, 0, NUMWORDS);
                Array.Copy(m_theChaining, 0, m_theM, NUMWORDS, NUMWORDS);

                /* Create parent block */
                InitParentBlock();
                Compress();

                /* Next block */
                myCount >>= 1;
            }

            /* Add back to the stack */
            m_theStack.Add(Arrays.CopyOf(m_theChaining, NUMWORDS));
        }

        /**
         * Compress final block.
         *
         * @param pDataLen the data length
         */
        private void CompressFinalBlock(int pDataLen)
        {
            /* Initialise state and compress message */
            InitChunkBlock(pDataLen, true);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            InitM(m_theBuffer);
#else
            InitM(m_theBuffer, 0);
#endif
            Compress();

            /* Finalise stack */
            ProcessStack();
        }

        /**
         * Process the stack.
         */
        private void ProcessStack()
        {
            /* Finalise stack */
            while (m_theStack.Count > 0)
            {
                /* Build the message to be hashed */
                uint[] myLeft = m_theStack[m_theStack.Count - 1];
                m_theStack.RemoveAt(m_theStack.Count - 1);

                Array.Copy(myLeft, 0, m_theM, 0, NUMWORDS);
                Array.Copy(m_theChaining, 0, m_theM, NUMWORDS, NUMWORDS);

                /* Create parent block */
                InitParentBlock();
                if (m_theStack.Count < 1)
                {
                    SetRoot();
                }
                Compress();
            }
        }

        /// <summary>
        /// Perform compression: the seven rounds of the BLAKE3 compression function over theV, with the message words
        /// in theM, followed by the output transformation.
        /// </summary>
        private void Compress()
        {
            uint[] v = m_theV;
            uint[] m = m_theM;

            uint v00 = v[0];
            uint v01 = v[1];
            uint v02 = v[2];
            uint v03 = v[3];
            uint v04 = v[4];
            uint v05 = v[5];
            uint v06 = v[6];
            uint v07 = v[7];
            uint v08 = v[8];
            uint v09 = v[9];
            uint v10 = v[10];
            uint v11 = v[11];
            uint v12 = v[12];
            uint v13 = v[13];
            uint v14 = v[14];
            uint v15 = v[15];

            uint m00 = m[0];
            uint m01 = m[1];
            uint m02 = m[2];
            uint m03 = m[3];
            uint m04 = m[4];
            uint m05 = m[5];
            uint m06 = m[6];
            uint m07 = m[7];
            uint m08 = m[8];
            uint m09 = m[9];
            uint m10 = m[10];
            uint m11 = m[11];
            uint m12 = m[12];
            uint m13 = m[13];
            uint m14 = m[14];
            uint m15 = m[15];

            for (int round = 0; round < ROUNDS; round++)
            {
                /* Apply to columns of V */
                v00 += v04 + m00;
                v12 = Integers.RotateRight(v12 ^ v00, 16);
                v08 += v12;
                v04 = Integers.RotateRight(v04 ^ v08, 12);
                v00 += v04 + m01;
                v12 = Integers.RotateRight(v12 ^ v00, 8);
                v08 += v12;
                v04 = Integers.RotateRight(v04 ^ v08, 7);

                v01 += v05 + m02;
                v13 = Integers.RotateRight(v13 ^ v01, 16);
                v09 += v13;
                v05 = Integers.RotateRight(v05 ^ v09, 12);
                v01 += v05 + m03;
                v13 = Integers.RotateRight(v13 ^ v01, 8);
                v09 += v13;
                v05 = Integers.RotateRight(v05 ^ v09, 7);

                v02 += v06 + m04;
                v14 = Integers.RotateRight(v14 ^ v02, 16);
                v10 += v14;
                v06 = Integers.RotateRight(v06 ^ v10, 12);
                v02 += v06 + m05;
                v14 = Integers.RotateRight(v14 ^ v02, 8);
                v10 += v14;
                v06 = Integers.RotateRight(v06 ^ v10, 7);

                v03 += v07 + m06;
                v15 = Integers.RotateRight(v15 ^ v03, 16);
                v11 += v15;
                v07 = Integers.RotateRight(v07 ^ v11, 12);
                v03 += v07 + m07;
                v15 = Integers.RotateRight(v15 ^ v03, 8);
                v11 += v15;
                v07 = Integers.RotateRight(v07 ^ v11, 7);

                /* Apply to diagonals of V */
                v00 += v05 + m08;
                v15 = Integers.RotateRight(v15 ^ v00, 16);
                v10 += v15;
                v05 = Integers.RotateRight(v05 ^ v10, 12);
                v00 += v05 + m09;
                v15 = Integers.RotateRight(v15 ^ v00, 8);
                v10 += v15;
                v05 = Integers.RotateRight(v05 ^ v10, 7);

                v01 += v06 + m10;
                v12 = Integers.RotateRight(v12 ^ v01, 16);
                v11 += v12;
                v06 = Integers.RotateRight(v06 ^ v11, 12);
                v01 += v06 + m11;
                v12 = Integers.RotateRight(v12 ^ v01, 8);
                v11 += v12;
                v06 = Integers.RotateRight(v06 ^ v11, 7);

                v02 += v07 + m12;
                v13 = Integers.RotateRight(v13 ^ v02, 16);
                v08 += v13;
                v07 = Integers.RotateRight(v07 ^ v08, 12);
                v02 += v07 + m13;
                v13 = Integers.RotateRight(v13 ^ v02, 8);
                v08 += v13;
                v07 = Integers.RotateRight(v07 ^ v08, 7);

                v03 += v04 + m14;
                v14 = Integers.RotateRight(v14 ^ v03, 16);
                v09 += v14;
                v04 = Integers.RotateRight(v04 ^ v09, 12);
                v03 += v04 + m15;
                v14 = Integers.RotateRight(v14 ^ v03, 8);
                v09 += v14;
                v04 = Integers.RotateRight(v04 ^ v09, 7);

                /*
                 * Permute the message words for the next round: m'[i] = m[SIGMA[i]], with the BLAKE3 message
                 * permutation SIGMA = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}.
                 */
                uint t0 = m00;
                uint t1 = m01;
                uint t2 = m02;
                uint t3 = m03;
                uint t4 = m04;
                uint t5 = m05;
                uint t6 = m06;
                uint t7 = m07;
                uint t8 = m08;
                uint t9 = m09;
                uint t10 = m10;
                uint t11 = m11;
                uint t12 = m12;
                uint t13 = m13;
                uint t14 = m14;
                uint t15 = m15;
                m00 = t2;
                m01 = t6;
                m02 = t3;
                m03 = t10;
                m04 = t7;
                m05 = t0;
                m06 = t4;
                m07 = t13;
                m08 = t1;
                m09 = t11;
                m10 = t12;
                m11 = t5;
                m12 = t9;
                m13 = t14;
                m14 = t15;
                m15 = t8;
            }

            v[0] = v00;
            v[1] = v01;
            v[2] = v02;
            v[3] = v03;
            v[4] = v04;
            v[5] = v05;
            v[6] = v06;
            v[7] = v07;
            v[8] = v08;
            v[9] = v09;
            v[10] = v10;
            v[11] = v11;
            v[12] = v12;
            v[13] = v13;
            v[14] = v14;
            v[15] = v15;

            AdjustChaining();
        }

        /**
         * Adjust Chaining after compression.
         */
        private void AdjustChaining()
        {
            /* If we are outputting */
            if (m_outputting)
            {
                /* Adjust full state */
                for (int i = 0; i < NUMWORDS; i++)
                {
                    m_theV[i] ^= m_theV[i + NUMWORDS];
                    m_theV[i + NUMWORDS] ^= m_theChaining[i];
                }

                /* Output state to buffer */
                Pack.UInt32_To_LE(m_theV, m_theBuffer, 0);
                m_thePos = 0;

                /* Else just build chain value */
            }
            else
            {
                /* Combine V into Chaining */
                for (int i = 0; i < NUMWORDS; i++)
                {
                    m_theChaining[i] = m_theV[i] ^ m_theV[i + NUMWORDS];
                }
            }
        }

        /**
         * Initialise null key.
         */
        private void InitNullKey()
        {
            Array.Copy(IV, 0, m_theK, 0, NUMWORDS);
        }

        /**
         * Initialise key.
         *
         * @param pKey the keyBytes
         */
        private void InitKey(byte[] pKey)
        {
            /* Copy message bytes into word array */
            Pack.LE_To_UInt32(pKey, 0, m_theK);
            m_theMode = KEYEDHASH;
        }

        /**
         * Initialise key from context.
         */
        private void InitKeyFromContext()
        {
            Array.Copy(m_theV, 0, m_theK, 0, NUMWORDS);
            m_theMode = DERIVEKEY;
        }

        /**
         * Initialise chunk block.
         *
         * @param pDataLen the dataLength
         * @param pFinal   is this the final chunk?
         */
        private void InitChunkBlock(int pDataLen, bool pFinal)
        {
            /* Initialise the block */
            Array.Copy(m_theCurrBytes == 0 ? m_theK : m_theChaining, 0, m_theV, 0, NUMWORDS);
            Array.Copy(IV, 0, m_theV, NUMWORDS, NUMWORDS >> 1);
            m_theV[COUNT0] = (uint)m_theCounter;
            m_theV[COUNT1] = (uint)(m_theCounter >> Integers.NumBits);
            m_theV[DATALEN] = (uint)pDataLen;
            m_theV[FLAGS] = (uint)(m_theMode
                + (m_theCurrBytes == 0 ? CHUNKSTART : 0)
                + (pFinal ? CHUNKEND : 0));

            /* * Adjust block count */
            m_theCurrBytes += pDataLen;
            if (m_theCurrBytes >= CHUNKLEN)
            {
                IncrementBlockCount();
                m_theV[FLAGS] |= CHUNKEND;
            }

            /* If we are single chunk */
            if (pFinal && m_theStack.Count < 1)
            {
                SetRoot();
            }
        }

        /**
         * Initialise parent block.
         */
        private void InitParentBlock()
        {
            /* Initialise the block */
            Array.Copy(m_theK, 0, m_theV, 0, NUMWORDS);
            Array.Copy(IV, 0, m_theV, NUMWORDS, NUMWORDS >> 1);
            m_theV[COUNT0] = 0;
            m_theV[COUNT1] = 0;
            m_theV[DATALEN] = BLOCKLEN;
            m_theV[FLAGS] = (uint)(m_theMode | PARENT);
        }

        /**
         * Initialise output block.
         */
        private void NextOutputBlock()
        {
            /* Increment the counter */
            m_theCounter++;

            /* Initialise the block */
            Array.Copy(m_theChaining, 0, m_theV, 0, NUMWORDS);
            Array.Copy(IV, 0, m_theV, NUMWORDS, NUMWORDS >> 1);
            m_theV[COUNT0] = (uint)m_theCounter;
            m_theV[COUNT1] = (uint)(m_theCounter >> Integers.NumBits);
            m_theV[DATALEN] = (uint)m_theOutputDataLen;
            m_theV[FLAGS] = (uint)m_theOutputMode;

            /* Generate output */
            Compress();
        }

        /**
         * IncrementBlockCount.
         */
        private void IncrementBlockCount()
        {
            m_theCounter++;
            m_theCurrBytes = 0;
        }

        /**
         * ResetBlockCount.
         */
        private void ResetBlockCount()
        {
            m_theCounter = 0;
            m_theCurrBytes = 0;
        }

        /**
         * Set root indication.
         */
        private void SetRoot()
        {
            m_theV[FLAGS] |= ROOT;
            m_theOutputMode = (int)m_theV[FLAGS];
            m_theOutputDataLen = (int)m_theV[DATALEN];
            m_theCounter = 0;
            m_outputting = true;
            m_outputAvailable = -1;
            Array.Copy(m_theV, 0, m_theChaining, 0, NUMWORDS);
        }
    }
}
