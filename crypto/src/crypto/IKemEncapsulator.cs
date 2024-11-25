using System;

namespace Org.BouncyCastle.Crypto
{
    public interface IKemEncapsulator
    {
        void Init(ICipherParameters parameters);

        int EncapsulationLength { get; }

        int SecretLength { get; }

        void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void Encapsulate(Span<byte> encapsulation, Span<byte> secret);
#endif
    }
}
