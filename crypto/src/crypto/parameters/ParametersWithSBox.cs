using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithSBox
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithSBox Create<TState>(ICipherParameters parameters, int sBoxLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithSBox result = new ParametersWithSBox(parameters, sBoxLength);
            action(result.m_sBox, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_sBox;

        public ParametersWithSBox(ICipherParameters parameters, byte[] sBox)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CopyBuffer(sBox);
        }

        public ParametersWithSBox(ICipherParameters parameters, byte[] sBox, int sBoxOff, int sBoxLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CopySegment(sBox, sBoxOff, sBoxLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithSBox(ICipherParameters parameters, ReadOnlySpan<byte> sBox)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = sBox.ToArray();
        }
#endif

        private ParametersWithSBox(ICipherParameters parameters, int sBoxLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CreateBuffer<byte>(sBoxLength);
        }

        public void CopySBoxTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_sBox, buf, off, len);

        public byte[] GetSBox() => Arrays.InternalCopyBuffer(m_sBox);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalSBox => m_sBox;
#endif

        public ICipherParameters Parameters => m_parameters;

        public int SBoxLength => m_sBox.Length;
    }
}
