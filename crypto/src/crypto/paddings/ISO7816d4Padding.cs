using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{
	/// <summary>
	/// A padder that adds the padding according to the scheme referenced in ISO 7816-4 - scheme 2 from ISO 9797-1.
	/// </summary>
	/// <remarks>
	/// The first byte is 0x80, the rest are 0x00.
	/// </remarks>
	public class ISO7816d4Padding
		: IBlockCipherPadding
	{
		/// <summary>
		/// Initialise the padder.
		/// </summary>
		/// <param name="random">A source of randomness (ignored for ISO7816-4).</param>
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
		/// <returns>The string "ISO7816-4".</returns>
		public string PaddingName => "ISO7816-4";

		/// <summary>
		/// Add padding to a given block.
		/// </summary>
		/// <param name="input">The array containing the data to be padded.</param>
		/// <param name="inOff">The offset into the input array where padding should start.</param>
		/// <returns>The number of bytes of padding added.</returns>
		public int AddPadding(byte[] input, int inOff)
		{
			int count = input.Length - inOff;

			input[inOff]= 0x80;
			while (++inOff < input.Length)
			{
				input[inOff] = 0x00;
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
			block[position++] = 0x80;
            block[position..].Fill(0x00);
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
			int position = -1, still00Mask = -1;
			int i = input.Length;
			while (--i >= 0)
			{
				int next = input[i];
				int match00Mask = ((next ^ 0x00) - 1) >> 31;
				int match80Mask = ((next ^ 0x80) - 1) >> 31;
				position ^= (i ^ position) & still00Mask & match80Mask;
				still00Mask &= match00Mask;
			}
			if (position < 0)
				throw new InvalidCipherTextException("pad block corrupted");

			return input.Length - position;
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
            int position = -1, still00Mask = -1;
            int i = block.Length;
            while (--i >= 0)
            {
                int next = block[i];
                int match00Mask = ((next ^ 0x00) - 1) >> 31;
                int match80Mask = ((next ^ 0x80) - 1) >> 31;
                position ^= (i ^ position) & still00Mask & match80Mask;
                still00Mask &= match00Mask;
            }
            if (position < 0)
                throw new InvalidCipherTextException("pad block corrupted");

            return block.Length - position;
        }
#endif
    }
}
