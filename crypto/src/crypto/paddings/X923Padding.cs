using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// A padder that adds X9.23 padding to a block.
    /// </summary>
    /// <remarks>
    /// If a <see cref="SecureRandom"/> is passed in, random padding is used; otherwise, the block is padded with zeros.
    /// </remarks>
    public class X923Padding
        : IBlockCipherPadding
    {
        private SecureRandom m_random = null;

        /// <summary>
        /// Initialise the padder.
        /// </summary>
        /// <param name="random">A source of randomness.</param>
        /// <remarks>
        /// If <paramref name="random"/> is <c>null</c>, zero padding is used; otherwise, the block is padded with random bytes.
        /// </remarks>
        public void Init(SecureRandom random)
        {
            m_random = random;
        }

        /// <summary>
        /// The algorithm name for the padding.
        /// </summary>
        /// <returns>The string "X9.23".</returns>
        public string PaddingName => "X9.23";

        /// <summary>
        /// Add padding to a given block.
        /// </summary>
        /// <param name="input">The array containing the data to be padded.</param>
        /// <param name="inOff">The offset into the input array where padding should start.</param>
        /// <returns>The number of bytes of padding added.</returns>
        public int AddPadding(byte[] input, int inOff)
        {
            int count = input.Length - inOff;
            if (count > 1)
            {
                if (m_random == null)
                {
                    Arrays.Fill(input, inOff, input.Length - 1, 0x00);
                }
                else
                {
                    m_random.NextBytes(input, inOff, count - 1);
                }
            }
            input[input.Length - 1] = (byte)count;
            return count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Add padding to a given block using Spans.
        /// </summary>
        /// <param name="block">The span to be padded.</param>
        /// <param name="position">The position where padding should start.</param>
        /// <returns>The number of bytes of padding added.</returns>
        public int AddPadding(Span<byte> block, int position)
        {
            int count = block.Length - position;
            if (count > 1)
            {
                var body = block[position..(block.Length - 1)];
                if (m_random == null)
                {
                    body.Fill(0x00);
                }
                else
                {
                    m_random.NextBytes(body);
                }
            }
            block[block.Length - 1] = (byte)count;
            return count;
        }
#endif

        /// <summary>
        /// Return the number of pad bytes found in the passed in block.
        /// </summary>
        /// <param name="input">The array containing the padded data.</param>
        /// <returns>The number of pad bytes.</returns>
        /// <exception cref="InvalidCipherTextException">If the padding is corrupted.</exception>
        public int PadCount(byte[] input)
        {
            int count = input[input.Length - 1];
            int position = input.Length - count;

            int failed = (position | (count - 1)) >> 31;
            if (failed != 0)
                throw new InvalidCipherTextException("pad block corrupted");

            return count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Return the number of pad bytes found in the passed in block using Spans.
        /// </summary>
        /// <param name="block">The read-only span containing the padded data.</param>
        /// <returns>The number of pad bytes.</returns>
        /// <exception cref="InvalidCipherTextException">If the padding is corrupted.</exception>
        public int PadCount(ReadOnlySpan<byte> block)
        {
            int count = block[block.Length - 1];
            int position = block.Length - count;

            int failed = (position | (count - 1)) >> 31;
            if (failed != 0)
                throw new InvalidCipherTextException("pad block corrupted");

            return count;
        }
#endif
    }
}
