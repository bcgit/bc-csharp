using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Encodings
{
	/**
	* ISO 9796-1 padding. Note in the light of recent results you should
	* only use this with RSA (rather than the "simpler" Rabin keys) and you
	* should never use it with anything other than a hash (ie. even if the
	* message is small don't sign the message, sign it's hash) or some "random"
	* value. See your favorite search engine for details.
	*/
	public class ISO9796d1Encoding
		: IAsymmetricBlockCipher
	{
        private static readonly byte[] Shadows = { 14, 3, 5, 8, 9, 4, 2, 15, 0, 13, 11, 6, 7, 10, 12, 1 };
        private static readonly byte[] Inverse = { 8, 15, 6, 1, 5, 2, 11, 12, 3, 4, 13, 10, 14, 9, 0, 7 };

		private readonly IAsymmetricBlockCipher m_cipher;
		private bool forEncryption;
		private int bitSize;
		private int padBits = 0;
		private BigInteger modulus;

		public ISO9796d1Encoding(IAsymmetricBlockCipher cipher)
		{
			m_cipher = cipher;
		}

		public string AlgorithmName => m_cipher.AlgorithmName + "/ISO9796-1Padding";

		public IAsymmetricBlockCipher UnderlyingCipher => m_cipher;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            m_cipher.Init(forEncryption, parameters);

            parameters = ParameterUtilities.IgnoreRandom(parameters);

            RsaKeyParameters kParam = (RsaKeyParameters)parameters;

            this.modulus = kParam.Modulus;
            this.bitSize = modulus.BitLength;

            this.forEncryption = forEncryption;
        }

        /**
		* return the input block size. The largest message we can process
		* is (key_size_in_bits + 3)/16, which in our world comes to
		* key_size_in_bytes / 2.
		*/
        public int GetInputBlockSize()
        {
            int baseBlockSize = m_cipher.GetInputBlockSize();

            if (forEncryption)
            {
                return (baseBlockSize + 1) / 2;
            }
            else
            {
                return baseBlockSize;
            }
        }

        /**
		* return the maximum possible size for the output.
		*/
        public int GetOutputBlockSize()
        {
            int baseBlockSize = m_cipher.GetOutputBlockSize();

            if (forEncryption)
            {
                return baseBlockSize;
            }
            else
            {
                return (baseBlockSize + 1) / 2;
            }
        }

        /**
		* set the number of bits in the next message to be treated as
		* pad bits.
		*/
        public void SetPadBits(int padBits)
		{
			if ((uint)padBits > 7U)
				throw new ArgumentOutOfRangeException(nameof(padBits));

			this.padBits = padBits;
		}

		/**
		* retrieve the number of pad bits in the last decoded message.
		*/
		public int GetPadBits() => padBits;

        public byte[] ProcessBlock(byte[] input, int inOff, int length)
        {
			return forEncryption
				?	EncodeBlock(input, inOff, length)
				:	DecodeBlock(input, inOff, length);
        }

        private byte[] EncodeBlock(byte[] input, int inOff, int inLen)
        {
            byte[] block = new byte[(bitSize + 7) / 8];
            int r = padBits + 1;
            int z = inLen;
            int t = (bitSize + 13) / 16;

            for (int i = 0; i < t; i += z)
            {
                if (i > t - z)
                {
                    Array.Copy(input, inOff + z - (t - i), block, block.Length - t, t - i);
                }
                else
                {
                    Array.Copy(input, inOff, block, block.Length - (i + z), z);
                }
            }

            for (int i = block.Length - 2 * t; i != block.Length; i += 2)
            {
                byte val = block[block.Length - t + i / 2];

                block[i] = (byte)(Shadows[val >> 4] << 4 | Shadows[val & 0x0F]);
                block[i + 1] = val;
            }

            block[block.Length - 2 * z] ^= (byte)r;
            block[block.Length - 1] = (byte)((block[block.Length - 1] << 4) | 0x06);

            int maxBit = 8 - (bitSize - 1) % 8;
            int offset = 0;

            if (maxBit != 8)
            {
                block[0] &= (byte)(0xFFU >> maxBit);
                block[0] |= (byte)(0x80U >> maxBit);
            }
            else
            {
                block[0] = 0x00;
                block[1] |= 0x80;
                offset = 1;
            }

            return m_cipher.ProcessBlock(block, offset, block.Length - offset);
        }

        /**
		* @exception InvalidCipherTextException if the decrypted block is not a valid ISO 9796 bit string
		*/
        private byte[] DecodeBlock(byte[] input, int inOff, int inLen)
        {
            byte[] block = m_cipher.ProcessBlock(input, inOff, inLen);
            int r = 1;
            int t = (bitSize + 13) / 16;

            BigInteger iS = new BigInteger(1, block);
            BigInteger iR;
            if ((iS.IntValue & 15) == 6)
            {
                iR = iS;
            }
            else
            {
                iR = modulus.Subtract(iS);

                if ((iR.IntValue & 15) != 6)
                    throw new InvalidCipherTextException("resulting integer iS or (modulus - iS) is not congruent to 6 mod 16");
            }

            block = iR.ToByteArrayUnsigned();

            if ((block[block.Length - 1] & 0xF) != 0x6)
                throw new InvalidCipherTextException("invalid forcing byte in block");

            block[block.Length - 1] = (byte)(block[block.Length - 1] >> 4 | Inverse[block[block.Length - 2] >> 4] << 4);

            block[0] = (byte)(Shadows[block[1] >> 4] << 4 | Shadows[block[1] & 0x0F]);

            bool boundaryFound = false;
            int boundary = 0;

            for (int i = block.Length - 1; i >= block.Length - 2 * t; i -= 2)
            {
                int val = Shadows[block[i] >> 4] << 4 | Shadows[block[i] & 0x0F];

                int x = val ^ block[i - 1];
                if (x != 0)
                {
                    if (boundaryFound)
                        throw new InvalidCipherTextException("invalid tsums in block");

                    boundaryFound = true;
                    r = x;
                    boundary = i - 1;
                }
            }

            block[boundary] = 0;

            byte[] nblock = new byte[(block.Length - boundary) / 2];

            for (int i = 0; i < nblock.Length; i++)
            {
                nblock[i] = block[2 * i + boundary + 1];
            }

            padBits = r - 1;

            return nblock;
        }
    }
}
