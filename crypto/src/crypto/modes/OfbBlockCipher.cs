using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Implements an Output-FeedBack (OFB) mode on top of a simple block cipher.
    /// </summary>
    public class OfbBlockCipher
        : IBlockCipherMode
    {
        private byte[]	IV;
        private byte[]	ofbV;
        private byte[]	ofbOutV;

        private readonly int			blockSize;
        private readonly IBlockCipher	cipher;

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="cipher">The block cipher to be used as the basis of the feedback mode.</param>
        /// <param name="blockSize">The block size in bits (must be a multiple of 8).</param>
        public OfbBlockCipher(
            IBlockCipher cipher,
            int         blockSize)
        {
            this.cipher = cipher;
            this.blockSize = blockSize / 8;

            this.IV = new byte[cipher.GetBlockSize()];
            this.ofbV = new byte[cipher.GetBlockSize()];
            this.ofbOutV = new byte[cipher.GetBlockSize()];
        }

        /// <summary>
        /// The underlying block cipher that we are wrapping.
        /// </summary>
        /// <returns>The underlying block cipher that we are wrapping.</returns>
        public IBlockCipher UnderlyingCipher => cipher;

        /// <summary>
        /// Initialise the cipher and, possibly, the initialisation vector (IV).
        /// </summary>
        /// <param name="forEncryption">Ignored by this OFB mode.</param>
        /// <param name="parameters">The key and other data required by the cipher (ParametersWithIV).</param>
        /// <exception cref="ArgumentException">If the parameters argument is inappropriate.</exception>
        public void Init(
            bool				forEncryption, //ignored by this OFB mode
            ICipherParameters	parameters)
        {
			if (parameters is ParametersWithIV ivParam)
            {
                byte[] iv = ivParam.GetIV();

                if (iv.Length < IV.Length)
                {
                    // prepend the supplied IV with zeros (per FIPS PUB 81)
                    Array.Copy(iv, 0, IV, IV.Length - iv.Length, iv.Length);
                    for (int i = 0; i < IV.Length - iv.Length; i++)
                    {
                        IV[i] = 0;
                    }
                }
                else
                {
                    Array.Copy(iv, 0, IV, 0, IV.Length);
                }

				parameters = ivParam.Parameters;
            }

			Reset();

            // if it's null, key is to be reused.
            if (parameters != null)
            {
                cipher.Init(true, parameters);
            }
        }

        /// <summary>
        /// The algorithm name and mode.
        /// </summary>
        /// <returns>The name of the underlying algorithm followed by "/OFB" and the block size in bits.</returns>
        public string AlgorithmName
        {
            get { return cipher.AlgorithmName + "/OFB" + (blockSize * 8); }
        }

        /// <summary>
        /// Indicates whether partial blocks are okay for this mode.
        /// </summary>
        public bool IsPartialBlockOkay
        {
            get { return true; }
        }

        /// <summary>
        /// Return the block size we are operating at.
        /// </summary>
        /// <returns>The block size we are operating at (in bytes).</returns>
        public int GetBlockSize()
        {
            return blockSize;
        }

        /// <summary>
        /// Process a block of data.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="inOff">The offset into the input buffer.</param>
        /// <param name="output">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>The number of bytes processed.</returns>
        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            Check.DataLength(input, inOff, blockSize, "input buffer too short");
            Check.OutputLength(output, outOff, blockSize, "output buffer too short");

            cipher.ProcessBlock(ofbV, 0, ofbOutV, 0);

            //
            // XOR the ofbV with the plaintext producing the cipher text (and
            // the next input block).
            //
            for (int i = 0; i < blockSize; i++)
            {
                output[outOff + i] = (byte)(ofbOutV[i] ^ input[inOff + i]);
            }

            //
            // change over the input block.
            //
            Array.Copy(ofbV, blockSize, ofbV, 0, ofbV.Length - blockSize);
            Array.Copy(ofbOutV, 0, ofbV, ofbV.Length - blockSize, blockSize);

            return blockSize;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Process a block of data using Spans.
        /// </summary>
        /// <param name="input">The input span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of bytes processed.</returns>
        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.DataLength(input, blockSize, "input buffer too short");
            Check.OutputLength(output, blockSize, "output buffer too short");

            cipher.ProcessBlock(ofbV, ofbOutV);

            //
            // XOR the ofbV with the plaintext producing the cipher text (and
            // the next input block).
            //
            for (int i = 0; i < blockSize; i++)
            {
                output[i] = (byte)(ofbOutV[i] ^ input[i]);
            }

            //
            // change over the input block.
            //
            Array.Copy(ofbV, blockSize, ofbV, 0, ofbV.Length - blockSize);
            Array.Copy(ofbOutV, 0, ofbV, ofbV.Length - blockSize, blockSize);

            return blockSize;
        }
#endif

        /// <summary>
        /// Reset the feedback vector back to the IV and reset the underlying cipher.
        /// </summary>
        public void Reset()
        {
            Array.Copy(IV, 0, ofbV, 0, IV.Length);
        }
    }
}
