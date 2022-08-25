using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Paddings
{
    /**
    * A padder that adds Pkcs7/Pkcs5 padding to a block.
    */
    public class Pkcs7Padding
        : IBlockCipherPadding
    {
        /**
        * Initialise the padder.
        *
        * @param random - a SecureRandom if available.
        */
        public void Init(
            SecureRandom random)
        {
            // nothing to do.
        }

        /**
        * Return the name of the algorithm the cipher implements.
        *
        * @return the name of the algorithm the cipher implements.
        */
        public string PaddingName
        {
            get { return "PKCS7"; }
        }

        /**
        * add the pad bytes to the passed in block, returning the
        * number of bytes added.
        */
        public int AddPadding(
            byte[]  input,
            int     inOff)
        {
            byte code = (byte)(input.Length - inOff);

            while (inOff < input.Length)
            {
                input[inOff] = code;
                inOff++;
            }

            return code;
        }

        /**
        * return the number of pad bytes present in the block.
        */
        public int PadCount(byte[] input)
        {
            byte countAsByte = input[input.Length - 1];
            int count = countAsByte;
            int position = input.Length - count;

            int failed = (position | (count - 1)) >> 31;
            for (int i = 0; i < input.Length; ++i)
            {
                failed |= (input[i] ^ countAsByte) & ~((i - position) >> 31);
            }
            if (failed != 0)
                throw new InvalidCipherTextException("pad block corrupted");

            return count;
        }
    }
}
