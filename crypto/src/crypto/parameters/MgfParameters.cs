using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
	/// <remarks>Parameters for mask derivation functions.</remarks>
    public sealed class MgfParameters
		: IDerivationParameters
    {
        private readonly byte[] m_seed;

		public MgfParameters(byte[] seed)
			: this(seed, 0, seed.Length)
        {
        }

		public MgfParameters(byte[] seed, int off, int len)
        {
            m_seed = Arrays.CopyOfRange(seed, off, len);
        }

        public byte[] GetSeed()
        {
            return (byte[])m_seed.Clone();
        }

        public void GetSeed(byte[] buffer, int offset)
        {
            m_seed.CopyTo(buffer, offset);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void GetSeed(Span<byte> output)
        {
            m_seed.CopyTo(output);
        }
#endif

        public int SeedLength => m_seed.Length;
    }
}
