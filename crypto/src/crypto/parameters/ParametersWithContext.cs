using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithContext
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithContext Create<TState>(ICipherParameters parameters, int contextLength,
            TState state, SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (contextLength < 0)
                throw new ArgumentOutOfRangeException(nameof(contextLength));

            ParametersWithContext result = new ParametersWithContext(parameters, contextLength);
            action(result.m_context, state);
            return result;
        }
#endif

        internal static ICipherParameters ApplyOptionalContext(ICipherParameters parameters, byte[] context) =>
            context == null ? parameters : new ParametersWithContext(parameters, context);

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_context;

        public ParametersWithContext(ICipherParameters parameters, byte[] context)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            m_parameters = parameters;
            m_context = (byte[])context.Clone();
        }

        public ParametersWithContext(ICipherParameters parameters, byte[] context, int contextOff, int contextLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            m_parameters = parameters;
            m_context = new byte[contextLen];
            Array.Copy(context, contextOff, m_context, 0, contextLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithContext(ICipherParameters parameters, ReadOnlySpan<byte> context)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = context.ToArray();
        }
#endif

        private ParametersWithContext(ICipherParameters parameters, int contextLength)
        {
            if (contextLength < 0)
                throw new ArgumentOutOfRangeException(nameof(contextLength));

            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = new byte[contextLength];
        }

        public void CopyContextTo(byte[] buf, int off, int len)
        {
            if (m_context.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            Array.Copy(m_context, 0, buf, off, len);
        }

        public byte[] GetContext() => (byte[])m_context.Clone();

        public int ContextLength => m_context.Length;

        public ICipherParameters Parameters => m_parameters;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> Context => m_context;
#endif
    }
}
