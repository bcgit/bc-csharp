using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    [Obsolete("Will be removed")]
    public interface IGcmExponentiator
	{
		void Init(byte[] x);
        void ExponentiateX(long pow, byte[] output);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void ExponentiateX(long pow, Span<byte> output);
#endif
    }
}
