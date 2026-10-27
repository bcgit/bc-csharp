using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fpe
{
    /// <summary>Base class for format-preserving encryption.</summary>
    public abstract class FpeEngine
    {
        /// <summary>The underlying block cipher.</summary>
        protected readonly IBlockCipher baseCipher;

        /// <summary>Whether the engine is initialised for encryption.</summary>
        protected bool forEncryption;
        /// <summary>The FPE parameters in use.</summary>
        protected FpeParameters fpeParameters;

        /// <summary>Create a new <see cref="FpeEngine"/>.</summary>
        /// <param name="baseCipher">The base cipher.</param>
        protected FpeEngine(IBlockCipher baseCipher)
        {
            this.baseCipher = baseCipher;
        }

        /// <summary>
        /// Process length bytes from inBuf, writing the output to outBuf.
        /// </summary>
        /// <returns>number of bytes output.</returns>
        /// <param name="inBuf">input data.</param>
        /// <param name="inOff">offset in input data to start at.</param>
        /// <param name="length">number of bytes to process.</param>
        /// <param name="outBuf">destination buffer.</param>
        /// <param name="outOff">offset to start writing at in destination buffer.</param>
        public virtual int ProcessBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
        {
            if (fpeParameters == null)
                throw new InvalidOperationException("FPE engine not initialized");
            if (length < 0)
                throw new ArgumentException("cannot be negative", "length");
            if (inBuf == null)
                throw new ArgumentNullException("inBuf");
            if (outBuf == null)
                throw new ArgumentNullException("outBuf");

            Check.DataLength(inBuf, inOff, length, "input buffer too short");
            Check.OutputLength(outBuf, outOff, length, "output buffer too short");

            if (forEncryption)
            {
                return EncryptBlock(inBuf, inOff, length, outBuf, outOff);
            }
            else
            {
                return DecryptBlock(inBuf, inOff, length, outBuf, outOff);
            }
        }

        /// <summary>Determine whether the given boolean property is set to true.</summary>
        /// <param name="propName">The name of the property.</param>
        /// <returns>true if the property is set to true, false otherwise.</returns>
        protected static bool IsOverrideSet(string propName) => Properties.GetBoolean(propName, false);

        /// <summary>
        /// Initialize the FPE engine for encryption/decryption.
        /// </summary>
        /// <returns>number of bytes output.</returns>
        /// <param name="forEncryption">true if initialising for encryption, false otherwise.</param>
        /// <param name="parameters ">the key and other parameters to use to set the engine up.</param>
        public abstract void Init(bool forEncryption, ICipherParameters parameters);

        /// <summary>Encrypt a block of data.</summary>
        /// <param name="inBuf">The input buffer.</param>
        /// <param name="inOff">The offset into <paramref name="inBuf"/> at which the data starts.</param>
        /// <param name="length">The length of the data.</param>
        /// <param name="outBuf">The output buffer.</param>
        /// <param name="outOff">The offset into <paramref name="outBuf"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        protected abstract int EncryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);

        /// <summary>Decrypt a block of data.</summary>
        /// <param name="inBuf">The input buffer.</param>
        /// <param name="inOff">The offset into <paramref name="inBuf"/> at which the data starts.</param>
        /// <param name="length">The length of the data.</param>
        /// <param name="outBuf">The output buffer.</param>
        /// <param name="outOff">The offset into <paramref name="outBuf"/> at which to start writing.</param>
        /// <returns>The number of bytes written.</returns>
        protected abstract int DecryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);
    }
}
