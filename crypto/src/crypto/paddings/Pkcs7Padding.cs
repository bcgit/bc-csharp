using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// A padder that adds PKCS7/PKCS5 padding to a block.
    /// </summary>
    public class Pkcs7Padding
        : IBlockCipherPadding
    {
        /// <summary>
        /// Initialise the padder.
        /// </summary>
        /// <param name="random">A source of randomness (ignored for PKCS7).</param>
        /// <remarks>
        /// For this padding scheme, the <paramref name="random"/> parameter is ignored.
        /// </remarks>
        public void Init(SecureRandom random)
        {
            // nothing to do.
        }

        /// <summary>
        /// The algorithm name for the padding.
        /// </summary>
        /// <returns>The string "PKCS7".</returns>
        public string PaddingName => "PKCS7";

        /// <summary>
        /// Add padding to a given block.
        /// </summary>
        /// <param name="input">The array containing the data to be padded.</param>
        /// <param name="inOff">The offset into the input array where padding should start.</param>
        /// <returns>The number of bytes of padding added.</returns>
        public int AddPadding(byte[] input, int inOff)
        {
            int count = input.Length - inOff;
            byte padValue = (byte)count;

            while (inOff < input.Length)
            {
                input[inOff++] = padValue;
            }

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
            byte padValue = (byte)count;
            block[position..].Fill(padValue);
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
            byte padValue = input[input.Length - 1];
            int count = padValue;
            int position = input.Length - count;

            int failed = (position | (count - 1)) >> 31;
            for (int i = 0; i < input.Length; ++i)
            {
                failed |= (input[i] ^ padValue) & ~((i - position) >> 31);
            }
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
            byte padValue = block[block.Length - 1];
            int count = padValue;
            int position = block.Length - count;

            int failed = (position | (count - 1)) >> 31;
            for (int i = 0; i < block.Length; ++i)
            {
                failed |= (block[i] ^ padValue) & ~((i - position) >> 31);
            }
            if (failed != 0)
                throw new InvalidCipherTextException("pad block corrupted");

            return count;
        }
#endif
    }
}
