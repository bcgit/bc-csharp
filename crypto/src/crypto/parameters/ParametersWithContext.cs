using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Cipher parameters accompanied by a context string.</summary>
    public class ParametersWithContext
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create parameters with a context value filled in via a callback.</summary>
        /// <param name="parameters">The underlying parameters.</param>
        /// <param name="contextLength">The length of the context in bytes.</param>
        /// <param name="state">The state to pass to the callback.</param>
        /// <param name="action">The callback that fills the context.</param>
        /// <returns>The parameters.</returns>
        public static ParametersWithContext Create<TState>(ICipherParameters parameters, int contextLength,
            TState state, System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithContext result = new ParametersWithContext(parameters, contextLength);
            action(result.m_context, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_context;

        /// <summary>Create a new <see cref="ParametersWithContext"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="context">The context.</param>
        public ParametersWithContext(ICipherParameters parameters, byte[] context)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = Arrays.CopyBuffer(context);
        }

        /// <summary>Create a new <see cref="ParametersWithContext"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="context">The context.</param>
        /// <param name="contextOff">The context off.</param>
        /// <param name="contextLen">The context len.</param>
        public ParametersWithContext(ICipherParameters parameters, byte[] context, int contextOff, int contextLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = Arrays.CopySegment(context, contextOff, contextLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a new <see cref="ParametersWithContext"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="context">The context.</param>
        public ParametersWithContext(ICipherParameters parameters, ReadOnlySpan<byte> context)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = context.ToArray();
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private ParametersWithContext(ICipherParameters parameters, int contextLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_context = Arrays.CreateBuffer<byte>(contextLength);
        }
#endif

        /// <summary>Gets the context length.</summary>
        public int ContextLength => m_context.Length;

        /// <summary>Copy the context to a buffer.</summary>
        /// <param name="buf">The buffer to copy to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        /// <param name="len">The number of bytes expected, which must equal the context length.</param>
        public void CopyContextTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_context, buf, off, len);

        /// <summary>Return the context.</summary>
        public byte[] GetContext() => Arrays.InternalCopyBuffer(m_context);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalContext => m_context;
#endif

        /// <summary>Gets the parameters.</summary>
        public ICipherParameters Parameters => m_parameters;
    }
}
