using System;

namespace Org.BouncyCastle.Crypto
{
    public interface IRawAgreement
    {
        void Init(ICipherParameters parameters);

        int AgreementSize { get; }

        void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void CalculateAgreement(ICipherParameters publicKey, Span<byte> output);
#endif
    }
}
