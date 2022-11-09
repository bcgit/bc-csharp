using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithIV
        : ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_iv;

        public ParametersWithIV(ICipherParameters parameters, byte[] iv)
            : this(parameters, iv, 0, iv.Length)
        {
        }

        public ParametersWithIV(ICipherParameters parameters, byte[] iv, int ivOff, int ivLen)
        {
            m_parameters = parameters;
            m_iv = Arrays.CopyOfRange(iv, ivOff, ivOff + ivLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithIV(ICipherParameters parameters, ReadOnlySpan<byte> iv)
        {
            m_parameters = parameters;
            m_iv = iv.ToArray();
        }
#endif

        public byte[] GetIV()
        {
            return (byte[])m_iv.Clone();
        }

        public ICipherParameters Parameters => m_parameters;
    }
}
