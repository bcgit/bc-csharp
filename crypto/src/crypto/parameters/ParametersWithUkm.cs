using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithUkm 
        : ICipherParameters
    {
        private readonly byte[] m_ukm;
        private readonly ICipherParameters m_parameters;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithUkm Create<TState>(ICipherParameters parameters, int ukmLength, TState state,
            SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (ukmLength < 0)
                throw new ArgumentOutOfRangeException(nameof(ukmLength));

            ParametersWithUkm result = new ParametersWithUkm(parameters, ukmLength);
            action(result.m_ukm, state);
            return result;
        }
#endif

        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm)
        {
            if (ukm == null)
                throw new ArgumentNullException(nameof(ukm));

            m_parameters = parameters;
            m_ukm = (byte[])ukm.Clone();
        }

        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm, int ukmOff,int ukmLen)
        {
            if (ukm == null)
                throw new ArgumentNullException(nameof(ukm));

            m_ukm = new byte[ukmLen];
            m_parameters = parameters;

            Array.Copy(ukm, ukmOff, m_ukm, 0, ukmLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithUkm(ICipherParameters parameters, ReadOnlySpan<byte> ukm)
        {
            m_parameters = parameters;
            m_ukm = ukm.ToArray();
        }
#endif
        private ParametersWithUkm(ICipherParameters parameters, int ukmLength)
        {
            if (ukmLength < 0)
                throw new ArgumentOutOfRangeException(nameof(ukmLength));

            m_parameters = parameters;
            m_ukm = new byte[ukmLength];
        }

        public void CopyUkmTo(byte[] buf, int off, int len)
        {
            if (m_ukm.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            Array.Copy(m_ukm, 0, buf, off, len);
        }

        public byte[] GetUkm() => (byte[])m_ukm.Clone();

        public int UkmLength => m_ukm.Length;

        public ICipherParameters Parameters => m_parameters;
    }
}
