using System;

namespace Org.BouncyCastle.Crypto
{
    /// <remarks>
    /// With FIPS PUB 202 a new kind of message digest was announced which supported extendable output, or variable digest sizes.
    /// This interface provides the extra method required to support variable output on a digest implementation.
    /// </remarks>
    public interface IXof
        : IDigest
    {
        /**
         * Output the results of the final calculation for this digest to outLen number of bytes.
         *
         * @param out output array to write the output bytes to.
         * @param outOff offset to start writing the bytes at.
         * @param outLen the number of output bytes requested.
         * @return the number of bytes written
         */
        int DoFinal(byte[] output, int outOff, int outLen);
    }
}
