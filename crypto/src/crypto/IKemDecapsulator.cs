using System;

namespace Org.BouncyCastle.Crypto
{
    public interface IKemDecapsulator
    {
        void Init(ICipherParameters parameters);

        int EncapsulationLength { get; }

        int SecretLength { get; }

        void Decapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void Decapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> secret);
#endif
    }
}
