using System;
using System.Collections.Generic;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
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
         * Message word permutations.
         */
        private static readonly byte[] SIGMA = { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

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
         * The indices.
         */
        private readonly byte[] m_theIndices = new byte[NUMWORDS << 1];

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

        public int GetByteLength() => BLOCKLEN;

        public string AlgorithmName => "BLAKE3";

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

        public int DoFinal(byte[] pOutput, int pOutOffset)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return OutputFinal(pOutput.AsSpan(pOutOffset, GetDigestSize()));
#else
            return OutputFinal(pOutput, pOutOffset, GetDigestSize());
#endif
        }

        public int OutputFinal(byte[] pOut, int pOutOffset, int pOutLen)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return OutputFinal(pOut.AsSpan(pOutOffset, pOutLen));
#else
            /* Reject if we are already outputting */
            if (m_outputting)
                throw new InvalidOperationException(ERR_OUTPUTTING);

            /* Build the required output */
            int length = Output(pOut, pOutOffset, pOutLen);

            /* reset the underlying digest and return the length */
            Reset();
            return length;
#endif
        }

        public int Output(byte[] pOut, int pOutOffset, int pOutLen)
        {
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
        public int DoFinal(Span<byte> output)
        {
            return OutputFinal(output[..GetDigestSize()]);
        }

        public int OutputFinal(Span<byte> output)
        {
            /* Reject if we are already outputting */
            if (m_outputting)
                throw new InvalidOperationException(ERR_OUTPUTTING);

            /* Build the required output */
            int length = Output(output);

            /* reset the underlying digest and return the length */
            Reset();
            return length;
        }

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

        public void Reset()
        {
            ResetBlockCount();
            m_thePos = 0;
            m_outputting = false;
            Arrays.Fill(m_theBuffer, 0);
        }

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

        /**
         * Perform compression.
         */
        private void Compress()
        {
            /* Initialise the buffers */
            InitIndices();

            /* Loop through the rounds */
            for (int round = 0; round < ROUNDS - 1; round++)
            {
                /* Perform the round and permuteM */
                PerformRound();
                PermuteIndices();
            }
            PerformRound();
            AdjustChaining();
        }

        /**
         * Perform a round.
         */
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void PerformRound()
        {
            /* Apply to columns of V */
            MixG(0, CHAINING0, CHAINING4, IV0, COUNT0);
            MixG(1, CHAINING1, CHAINING5, IV1, COUNT1);
            MixG(2, CHAINING2, CHAINING6, IV2, DATALEN);
            MixG(3, CHAINING3, CHAINING7, IV3, FLAGS);

            /* Apply to diagonals of V */
            MixG(4, CHAINING0, CHAINING5, IV2, FLAGS);
            MixG(5, CHAINING1, CHAINING6, IV3, COUNT0);
            MixG(6, CHAINING2, CHAINING7, IV0, COUNT1);
            MixG(7, CHAINING3, CHAINING4, IV1, DATALEN);
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
         * Mix function G.
         *
         * @param msgIdx the message index
         * @param posA   position A in V
         * @param posB   position B in V
         * @param posC   position C in V
         * @param posD   poistion D in V
         */
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void MixG(int msgIdx, int posA, int posB, int posC, int posD)
        {
            /* Determine indices */
            int msg = msgIdx << 1;

            /* Perform the Round */
            m_theV[posA] += m_theV[posB] + m_theM[m_theIndices[msg++]];
            m_theV[posD] = Integers.RotateRight(m_theV[posD] ^ m_theV[posA], 16);
            m_theV[posC] += m_theV[posD];
            m_theV[posB] = Integers.RotateRight(m_theV[posB] ^ m_theV[posC], 12);
            m_theV[posA] += m_theV[posB] + m_theM[m_theIndices[msg]];
            m_theV[posD] = Integers.RotateRight(m_theV[posD] ^ m_theV[posA], 8);
            m_theV[posC] += m_theV[posD];
            m_theV[posB] = Integers.RotateRight(m_theV[posB] ^ m_theV[posC], 7);
        }

        /**
         * initialise the indices.
         */
        private void InitIndices()
        {
            for (byte i = 0; i < m_theIndices.Length; i++)
            {
                m_theIndices[i] = i;
            }
        }

        /**
         * PermuteIndices.
         */
        private void PermuteIndices()
        {
            for (byte i = 0; i < m_theIndices.Length; i++)
            {
                m_theIndices[i] = SIGMA[m_theIndices[i]];
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
