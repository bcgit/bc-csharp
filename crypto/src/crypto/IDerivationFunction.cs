using System;

namespace Org.BouncyCastle.Crypto
{
    /**
     * base interface for general purpose byte derivation functions.
     */
    public interface IDerivationFunction
    {
        void Init(IDerivationParameters parameters);

        /**
         * return the message digest used as the basis for the function
         */
        IDigest Digest { get; }

        int GenerateBytes(byte[] output, int outOff, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        int GenerateBytes(Span<byte> output);
#endif
    }
}
