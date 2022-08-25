using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{

    /// <summary> A padder that adds Null byte padding to a block.</summary>
    public class ZeroBytePadding : IBlockCipherPadding
    {
        /// <summary> Return the name of the algorithm the cipher implements.
        ///
        /// </summary>
        /// <returns> the name of the algorithm the cipher implements.
        /// </returns>
        public string PaddingName
        {
            get { return "ZeroBytePadding"; }
        }

		/// <summary> Initialise the padder.
        ///
        /// </summary>
        /// <param name="random">- a SecureRandom if available.
        /// </param>
        public void Init(SecureRandom random)
        {
            // nothing to do.
        }

        /// <summary> add the pad bytes to the passed in block, returning the
        /// number of bytes added.
        /// </summary>
        public int AddPadding(
			byte[]	input,
			int		inOff)
        {
            int added = (input.Length - inOff);

            while (inOff < input.Length)
            {
                input[inOff] = (byte) 0;
                inOff++;
            }

            return added;
        }

        /// <summary> return the number of pad bytes present in the block.</summary>
        public int PadCount(byte[] input)
        {
            int count = 0, still00Mask = -1;
            int i = input.Length;
            while (--i >= 0)
            {
                int next = input[i];
                int match00Mask = ((next ^ 0x00) - 1) >> 31;
                still00Mask &= match00Mask;
                count -= still00Mask;
            }
            return count;
        }
    }
}
