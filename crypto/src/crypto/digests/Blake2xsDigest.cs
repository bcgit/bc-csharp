using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /*
      The BLAKE2 cryptographic hash function was designed by Jean-
      Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
      Winnerlein.

      Reference Implementation and Description can be found at: https://blake2.net/blake2x.pdf
     */

    /**
     * Implementation of the eXtendable Output Function (XOF) BLAKE2xs.
     * <p/>
     * BLAKE2xs offers a built-in keying mechanism to be used directly
     * for authentication ("Prefix-MAC") rather than a HMAC construction.
     * <p/>
     * BLAKE2xs offers a built-in support for a salt for randomized hashing
     * and a personal string for defining a unique hash function for each application.
     * <p/>
     * BLAKE2xs is optimized for 32-bit platforms and produces digests of any size
     * between 1 and 2^16-2 bytes. The length can also be unknown and then the maximum
     * length will be 2^32 blocks of 32 bytes.
     */
    public sealed class Blake2xsDigest
        : IXof
    {
        /**
         * Magic number to indicate an unknown length of digest
         */
        public const int UnknownDigestLength = 65535;

        private const int DigestLength = 32;
        private const long MaxNumberBlocks = 1L << 32;

        /**
         * Expected digest length for the xof. It can be unknown.
         */
        private int digestLength;

        /**
         * Root hash that will take the updates
         */
        private Blake2sDigest hash;

        /**
         * Digest of the root hash
         */
        private byte[] h0 = null;

        /**
         * Digest of each round of the XOF
         */
        private byte[] buf = new byte[32];

        /**
         * Current position for a round
         */
        private int bufPos = 32;

        /**
         * Overall position of the digest. It is useful when the length is known
         * in advance to get last block length.
         */
        private int digestPos = 0;

        /**
         * Keep track of the round number to detect the end of the digest after
         * 2^32 blocks of 32 bytes.
         */
        private long blockPos = 0;

        /**
         * Current node offset incremented by 1 every round.
         */
        private long nodeOffset;

        /**
         * BLAKE2xs for hashing with unknown digest length
         */
        public Blake2xsDigest()
            : this(UnknownDigestLength)
        {
        }

        /**
         * BLAKE2xs for hashing
         *
         * @param digestBytes The desired digest length in bytes. Must be above 1 and less than 2^16-1
         */
        public Blake2xsDigest(int digestBytes)
            : this(digestBytes, null, null, null)
        {
        }

        /**
         * BLAKE2xs with key
         *
         * @param digestBytes The desired digest length in bytes. Must be above 1 and less than 2^16-1
         * @param key         A key up to 32 bytes or null
         */
        public Blake2xsDigest(int digestBytes, byte[] key)
            : this(digestBytes, key, null, null)
        {
        }

        /**
         * BLAKE2xs with key, salt and personalization
         *
         * @param digestBytes     The desired digest length in bytes. Must be above 1 and less than 2^16-1
         * @param key             A key up to 32 bytes or null
         * @param salt            8 bytes or null
         * @param personalization 8 bytes or null
         */
        public Blake2xsDigest(int digestBytes, byte[] key, byte[] salt, byte[] personalization)
        {
            if (digestBytes < 1 || digestBytes > UnknownDigestLength)
                throw new ArgumentException("BLAKE2xs digest length must be between 1 and 2^16-1");

            digestLength = digestBytes;
            nodeOffset = ComputeNodeOffset();
            hash = new Blake2sDigest(DigestLength, key, salt, personalization, nodeOffset);
        }

        public Blake2xsDigest(Blake2xsDigest digest)
        {
            digestLength = digest.digestLength;
            hash = new Blake2sDigest(digest.hash);
            h0 = Arrays.Clone(digest.h0);
            buf = Arrays.Clone(digest.buf);
            bufPos = digest.bufPos;
            digestPos = digest.digestPos;
            blockPos = digest.blockPos;
            nodeOffset = digest.nodeOffset;
        }

        /**
         * Return the algorithm name.
         *
         * @return the algorithm name
         */
        public string AlgorithmName => "BLAKE2xs";

        /**
         * Return the size in bytes of the digest produced by this message digest.
         *
         * @return the size in bytes of the digest produced by this message digest.
         */
        public int GetDigestSize() => digestLength;

        /**
         * Return the size in bytes of the internal buffer the digest applies its
         * compression function to.
         *
         * @return byte length of the digest's internal buffer.
         */
        public int GetByteLength() => hash.GetByteLength();

        /**
         * Return the maximum size in bytes the digest can produce when the length
         * is unknown
         *
         * @return byte length of the largest digest with unknown length
         */
        public long GetUnknownMaxLength()
        {
            return MaxNumberBlocks * DigestLength;
        }

        /**
         * Update the message digest with a single byte.
         *
         * @param in the input byte to be entered.
         */
        public void Update(byte b)
        {
            hash.Update(b);
        }

        /**
         * Update the message digest with a block of bytes.
         *
         * @param in    the byte array containing the data.
         * @param inOff the offset into the byte array where the data starts.
         * @param len   the length of the data.
         */
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            hash.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            hash.BlockUpdate(input);
        }
#endif

        /**
         * Reset the digest back to its initial state. The key, the salt and the
         * personal string will remain for further computations.
         */
        public void Reset()
        {
            hash.Reset();

            h0 = null;
            bufPos = DigestLength;
            digestPos = 0;
            blockPos = 0;
            nodeOffset = ComputeNodeOffset();
        }

        /**
         * Close the digest, producing the final digest value. The doFinal() call
         * leaves the digest reset. Key, salt and personal string remain.
         *
         * @param out       the array the digest is to be copied into.
         * @param outOffset the offset into the out array the digest is to start at.
         */
        public int DoFinal(byte[] output, int outOff)
        {
            return OutputFinal(output, outOff, digestLength);
        }

        /**
         * Close the digest, producing the final digest value. The doFinal() call
         * leaves the digest reset. Key, salt, personal string remain.
         *
         * @param out    output array to write the output bytes to.
         * @param outOff offset to start writing the bytes at.
         * @param outLen the number of output bytes requested.
         */
        public int OutputFinal(byte[] output, int outOff, int outLen)
        {
            int ret = Output(output, outOff, outLen);

            Reset();

            return ret;
        }

        /**
         * Start outputting the results of the final calculation for this digest. Unlike doFinal, this method
         * will continue producing output until the Xof is explicitly reset, or signals otherwise.
         *
         * @param out    output array to write the output bytes to.
         * @param outOff offset to start writing the bytes at.
         * @param outLen the number of output bytes requested.
         * @return the number of bytes written
         */
        public int Output(byte[] output, int outOff, int outLen)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Output(output.AsSpan(outOff, outLen));
#else
            if (h0 == null)
            {
                h0 = new byte[hash.GetDigestSize()];
                hash.DoFinal(h0, 0);
            }

            if (digestLength != UnknownDigestLength)
            {
                if (digestPos + outLen > digestLength)
                    throw new ArgumentException("Output length is above the digest length");
            }
            else if (blockPos << 5 >= GetUnknownMaxLength())
            {
                throw new ArgumentException("Maximum length is 2^32 blocks of 32 bytes");
            }

            for (int i = 0; i < outLen; i++)
            {
                if (bufPos >= DigestLength)
                {
                    Blake2sDigest h = new Blake2sDigest(ComputeStepLength(), DigestLength, nodeOffset);
                    h.BlockUpdate(h0, 0, h0.Length);

                    Arrays.Fill(buf, 0);
                    h.DoFinal(buf, 0);
                    bufPos = 0;
                    nodeOffset++;
                    blockPos++;
                }
                output[outOff + i] = buf[bufPos];
                bufPos++;
                digestPos++;
            }

            return outLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            return OutputFinal(output[..digestLength]);
        }

        public int OutputFinal(Span<byte> output)
        {
            int ret = Output(output);

            Reset();

            return ret;
        }

        public int Output(Span<byte> output)
        {
            int outLen = output.Length;
            if (h0 == null)
            {
                h0 = new byte[hash.GetDigestSize()];
                hash.DoFinal(h0);
            }

            if (digestLength != UnknownDigestLength)
            {
                if (digestPos + outLen > digestLength)
                    throw new ArgumentException("Output length is above the digest length");
            }
            else if (blockPos << 5 >= GetUnknownMaxLength())
            {
                throw new ArgumentException("Maximum length is 2^32 blocks of 32 bytes");
            }

            for (int i = 0; i < outLen; i++)
            {
                if (bufPos >= DigestLength)
                {
                    Blake2sDigest h = new Blake2sDigest(ComputeStepLength(), DigestLength, nodeOffset);
                    h.BlockUpdate(h0);

                    Arrays.Fill(buf, 0);
                    h.DoFinal(buf);
                    bufPos = 0;
                    nodeOffset++;
                    blockPos++;
                }
                output[i] = buf[bufPos];
                bufPos++;
                digestPos++;
            }

            return outLen;
        }
#endif

        // get the next round length. If the length is unknown, the digest length is always the maximum.
        private int ComputeStepLength()
        {
            if (digestLength == UnknownDigestLength)
                return DigestLength;

            return System.Math.Min(DigestLength, digestLength - digestPos);
        }

        private long ComputeNodeOffset()
        {
            return digestLength * 0x100000000L;
        }
    }
}
