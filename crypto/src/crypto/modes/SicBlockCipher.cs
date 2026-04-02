using System;

using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Implements the Segmented Integer Counter (SIC) mode on top of a simple block cipher.
    /// </summary>
    /// <remarks>
    /// This mode is also known as CTR mode.
    /// </remarks>
    public class SicBlockCipher
        : IBlockCipherMode
    {
        private readonly IBlockCipher cipher;
        private readonly int blockSize;
        private readonly byte[] counter;
        private readonly byte[] counterOut;
        private byte[] IV;

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="cipher">The block cipher to be used.</param>
        public SicBlockCipher(IBlockCipher cipher)
        {
            this.cipher = cipher;
            this.blockSize = cipher.GetBlockSize();
            this.counter = new byte[blockSize];
            this.counterOut = new byte[blockSize];
            this.IV = new byte[blockSize];
        }

        /// <summary>
        /// The underlying block cipher that we are wrapping.
        /// </summary>
        /// <returns>The underlying block cipher that we are wrapping.</returns>
        public IBlockCipher UnderlyingCipher => cipher;

        /// <summary>
        /// Initialise the cipher and, possibly, the initialisation vector (IV).
        /// </summary>
        /// <param name="forEncryption">Ignored by CTR mode.</param>
        /// <param name="parameters">The key and other data required by the cipher (ParametersWithIV).</param>
        /// <exception cref="ArgumentException">If the parameters argument is inappropriate.</exception>
        public virtual void Init(
            bool				forEncryption, //ignored by this CTR mode
            ICipherParameters	parameters)
        {
            if (!(parameters is ParametersWithIV ivParam))
                throw new ArgumentException("CTR/SIC mode requires ParametersWithIV", "parameters");

            this.IV = Arrays.Clone(ivParam.GetIV());

            if (blockSize < IV.Length)
                throw new ArgumentException("CTR/SIC mode requires IV no greater than: " + blockSize + " bytes.");

            int maxCounterSize = System.Math.Min(8, blockSize / 2);
            if (blockSize - IV.Length > maxCounterSize)
                throw new ArgumentException("CTR/SIC mode requires IV of at least: " + (blockSize - maxCounterSize) + " bytes.");

            Reset();

            // if null it's an IV changed only.
            if (ivParam.Parameters != null)
            {
                cipher.Init(true, ivParam.Parameters);
            }
        }

        /// <summary>
        /// The algorithm name and mode.
        /// </summary>
        /// <returns>The name of the underlying algorithm followed by "/SIC".</returns>
        public virtual string AlgorithmName
        {
            get { return cipher.AlgorithmName + "/SIC"; }
        }

        /// <summary>
        /// Indicates whether partial blocks are okay for this mode.
        /// </summary>
        public virtual bool IsPartialBlockOkay
        {
            get { return true; }
        }

        /// <summary>
        /// Return the block size of the underlying cipher.
        /// </summary>
        /// <returns>The block size of the underlying cipher (in bytes).</returns>
        public virtual int GetBlockSize()
        {
            return cipher.GetBlockSize();
        }

        /// <summary>
        /// Process a block of data.
        /// </summary>
        /// <param name="input">The input buffer.</param>
        /// <param name="inOff">The offset into the input buffer.</param>
        /// <param name="output">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>The number of bytes processed.</returns>
        public virtual int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            cipher.ProcessBlock(counter, 0, counterOut, 0);

            //
            // XOR the counterOut with the plaintext producing the cipher text
            //
            for (int i = 0; i < counterOut.Length; i++)
            {
                output[outOff + i] = (byte)(counterOut[i] ^ input[inOff + i]);
            }

            // Increment the counter
            int j = counter.Length;
            while (--j >= 0 && ++counter[j] == 0)
            {
            }

            return counter.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Process a block of data using Spans.
        /// </summary>
        /// <param name="input">The input span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of bytes processed.</returns>
        public virtual int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            cipher.ProcessBlock(counter, 0, counterOut, 0);

            //
            // XOR the counterOut with the plaintext producing the cipher text
            //
            for (int i = 0; i < counterOut.Length; i++)
            {
                output[i] = (byte)(counterOut[i] ^ input[i]);
            }

            // Increment the counter
            int j = counter.Length;
            while (--j >= 0 && ++counter[j] == 0)
            {
            }

            return counter.Length;
        }
#endif

        /// <summary>
        /// Reset the chaining vector back to the IV and reset the underlying cipher.
        /// </summary>
        public virtual void Reset()
        {
            Arrays.Fill(counter, (byte)0);
            Array.Copy(IV, 0, counter, 0, IV.Length);
        }
    }
}
