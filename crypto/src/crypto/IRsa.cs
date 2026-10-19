using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for the RSA core operation, converting between byte arrays and integers around the raw transform.
    /// </summary>
    public interface IRsa
    {
        /// <summary>Initialise the RSA core.</summary>
        /// <param name="forEncryption">
        /// true for encryption (the public operation), false for decryption (the private operation).
        /// </param>
        /// <param name="parameters">The RSA key parameters.</param>
        void Init(bool forEncryption, ICipherParameters parameters);
        int GetInputBlockSize();
        int GetOutputBlockSize();
        /// <summary>
        /// Convert an input block to an integer, checking that it is in the range accepted by the core.
        /// </summary>
        /// <param name="buf">The buffer holding the block.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the block starts.</param>
        /// <param name="len">The length of the block.</param>
        /// <returns>The integer value of the block.</returns>
        BigInteger ConvertInput(byte[] buf, int off, int len);
        /// <summary>Apply the RSA transform to an integer.</summary>
        /// <param name="input">The input value.</param>
        /// <returns>The result of the transform.</returns>
        BigInteger ProcessBlock(BigInteger input);
        /// <summary>Convert the result of the RSA transform to bytes.</summary>
        /// <param name="result">The result of the transform.</param>
        /// <returns>The output block.</returns>
        byte[] ConvertOutput(BigInteger result);
    }
}
