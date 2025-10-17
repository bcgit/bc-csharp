using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithIV
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api] 'parameter' -> 'parameters'
        public static ParametersWithIV Create<TState>(ICipherParameters parameter, int ivLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithIV result = new ParametersWithIV(parameter, ivLength);
            action(result.m_iv, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_iv;

        public ParametersWithIV(ICipherParameters parameters, byte[] iv)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CopyBuffer(iv);
        }

        public ParametersWithIV(ICipherParameters parameters, byte[] iv, int ivOff, int ivLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CopySegment(iv, ivOff, ivLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithIV(ICipherParameters parameters, ReadOnlySpan<byte> iv)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = iv.ToArray();
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private ParametersWithIV(ICipherParameters parameters, int ivLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CreateBuffer<byte>(ivLength);
        }
#endif

        public void CopyIVTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_iv, buf, off, len);

        public byte[] GetIV() => Arrays.InternalCopyBuffer(m_iv);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalIV => m_iv;
#endif

        public int IVLength => m_iv.Length;

        public ICipherParameters Parameters => m_parameters;
    }
}
