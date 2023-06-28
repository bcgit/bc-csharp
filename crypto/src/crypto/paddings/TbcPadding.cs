using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary> A padder that adds Trailing-Bit-Compliment padding to a block.</summary>
    /// <remarks>This padding pads the block out compliment of the last bit of the plain text.</remarks>
    public class TbcPadding
		: IBlockCipherPadding
    {
        public virtual void Init(SecureRandom random)
        {
            // nothing to do.
        }

        public string PaddingName => "TBC";

        public virtual int AddPadding(byte[] input, int inOff)
        {
            int count = input.Length - inOff;
            byte lastByte = inOff > 0 ? input[inOff - 1] : input[input.Length - 1];
            byte padValue = (byte)((lastByte & 1) - 1);

            while (inOff < input.Length)
            {
                input[inOff++] = padValue;
            }

            return count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int AddPadding(Span<byte> block, int position)
        {
            byte lastByte = position > 0 ? block[position - 1] : block[block.Length - 1];
            byte padValue = (byte)((lastByte & 1) - 1);

            var padding = block[position..];
            padding.Fill(padValue);
            return padding.Length;
        }
#endif

        public virtual int PadCount(byte[] input)
        {
            int i = input.Length;
            int code = input[--i], count = 1, countingMask = -1;
            while (--i >= 0)
            {
                int next = input[i];
                int matchMask = ((next ^ code) - 1) >> 31;
                countingMask &= matchMask;
                count -= countingMask;
            }
            return count;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int PadCount(ReadOnlySpan<byte> block)
        {
            int i = block.Length;
            int code = block[--i], count = 1, countingMask = -1;
            while (--i >= 0)
            {
                int next = block[i];
                int matchMask = ((next ^ code) - 1) >> 31;
                countingMask &= matchMask;
                count -= countingMask;
            }
            return count;
        }
#endif
    }
}
