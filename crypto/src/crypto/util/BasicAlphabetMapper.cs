using System;
using System.Collections;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Utilities
{
    /**
     * A basic alphabet mapper that just creates a mapper based on the
     * passed in array of characters.
     */
    public class BasicAlphabetMapper
       : IAlphabetMapper
    {
        private readonly IDictionary indexMap = Platform.CreateHashtable();
        private readonly IDictionary charMap = Platform.CreateHashtable();

        /**
         * Base constructor.
         *
         * @param alphabet a string of characters making up the alphabet.
         */
        public BasicAlphabetMapper(string alphabet) :
            this(alphabet.ToCharArray())
        {
        }

        /**
         * Base constructor.
         *
         * @param alphabet an array of characters making up the alphabet.
         */
        public BasicAlphabetMapper(char[] alphabet)
        {
            for (int i = 0; i != alphabet.Length; i++)
            {
                if (indexMap.Contains(alphabet[i]))
                {
                    throw new ArgumentException("duplicate key detected in alphabet: " + alphabet[i]);
                }
                indexMap.Add(alphabet[i], i);
                charMap.Add(i, alphabet[i]);
            }
        }

        public int Radix
        {
            get { return indexMap.Count; }
        }

        public byte[] ConvertToIndexes(char[] input)
        {
            byte[] outBuf;

            if (indexMap.Count <= 256)
            {
                outBuf = new byte[input.Length];
                for (int i = 0; i != input.Length; i++)
                {
                    outBuf[i] = (byte)(int)indexMap[input[i]];
                }
            }
            else
            {
                outBuf = new byte[input.Length * 2];
                for (int i = 0; i != input.Length; i++)
                {
                    int idx = (int)indexMap[input[i]];
                    outBuf[i * 2] = (byte)((idx >> 8) & 0xff);
                    outBuf[i * 2 + 1] = (byte)(idx & 0xff);
                }
            }

            return outBuf;
        }

        public char[] ConvertToChars(byte[] input)
        {
            char[] outBuf;

            if (charMap.Count <= 256)
            {
                outBuf = new char[input.Length];
                for (int i = 0; i != input.Length; i++)
                {
                    outBuf[i] = (char)charMap[input[i] & 0xff];
                }
            }
            else
            {
                if ((input.Length & 0x1) != 0)
                {
                    throw new ArgumentException("two byte radix and input string odd.Length");
                }

                outBuf = new char[input.Length / 2];
                for (int i = 0; i != input.Length; i += 2)
                {
                    outBuf[i / 2] = (char)charMap[((input[i] << 8) & 0xff00) | (input[i + 1] & 0xff)];
                }
            }

            return outBuf;
        }
    }
}
