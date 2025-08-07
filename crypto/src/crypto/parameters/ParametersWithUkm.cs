using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithUkm 
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithUkm Create<TState>(ICipherParameters parameters, int ukmLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithUkm result = new ParametersWithUkm(parameters, ukmLength);
            action(result.m_ukm, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_ukm;

        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CopyBuffer(ukm);
        }

        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm, int ukmOff,int ukmLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CopySegment(ukm, ukmOff, ukmLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithUkm(ICipherParameters parameters, ReadOnlySpan<byte> ukm)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = ukm.ToArray();
        }
#endif

        private ParametersWithUkm(ICipherParameters parameters, int ukmLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CreateBuffer<byte>(ukmLength);
        }

        public void CopyUkmTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_ukm, buf, off, len);

        public byte[] GetUkm() => Arrays.InternalCopyBuffer(m_ukm);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalUkm => m_ukm;
#endif

        public ICipherParameters Parameters => m_parameters;

        public int UkmLength => m_ukm.Length;
    }
}
