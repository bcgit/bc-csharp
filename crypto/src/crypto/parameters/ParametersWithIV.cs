using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include an Initialisation Vector (IV).
    /// </summary>
    public class ParametersWithIV
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api] 'parameter' -> 'parameters'
        /// <summary>
        /// Create a new <see cref="ParametersWithIV"/> instance using a span action.
        /// </summary>
        /// <typeparam name="TState">The type of the state object.</typeparam>
        /// <param name="parameter">The base parameters.</param>
        /// <param name="ivLength">The length of the IV in bytes.</param>
        /// <param name="state">The state object for the action.</param>
        /// <param name="action">The action to initialize the IV.</param>
        /// <returns>A new <see cref="ParametersWithIV"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="action"/> is null.</exception>
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

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="iv">The initialization vector.</param>
        public ParametersWithIV(ICipherParameters parameters, byte[] iv)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CopyBuffer(iv);
        }

        /// <summary>
        /// Constructor with offset and length for IV.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="iv">The initialization vector array.</param>
        /// <param name="ivOff">The offset into the IV array.</param>
        /// <param name="ivLen">The length of the IV to use.</param>
        public ParametersWithIV(ICipherParameters parameters, byte[] iv, int ivOff, int ivLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CopySegment(iv, ivOff, ivLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Constructor using Span for IV.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="iv">The initialization vector span.</param>
        public ParametersWithIV(ICipherParameters parameters, ReadOnlySpan<byte> iv)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = iv.ToArray();
        }

        /// <summary>
        /// Initialise the IV with a given length.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="ivLength">The length of the IV in bytes.</param>
        private ParametersWithIV(ICipherParameters parameters, int ivLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = Arrays.CreateBuffer<byte>(ivLength);
        }
#endif

        /// <summary>
        /// Copy the IV into a segment of a destination buffer.
        /// </summary>
        /// <param name="buf">The destination buffer.</param>
        /// <param name="off">The offset into the destination buffer.</param>
        /// <param name="len">The length to copy.</param>
        public void CopyIVTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_iv, buf, off, len);

        /// <summary>
        /// Return a copy of the IV.
        /// </summary>
        /// <returns>A new array containing the IV bytes.</returns>
        public byte[] GetIV() => Arrays.InternalCopyBuffer(m_iv);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Allows internal access to the IV as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        internal ReadOnlySpan<byte> InternalIV => m_iv;
#endif

        /// <summary>
        /// Return the length of the IV in bytes.
        /// </summary>
        /// <returns>The length of the IV in bytes.</returns>
        public int IVLength => m_iv.Length;

        /// <summary>
        /// Return the base parameters (e.g., KeyParameter) associated with this IV.
        /// </summary>
        /// <returns>The parameters wrapped by this IV.</returns>
        public ICipherParameters Parameters => m_parameters;
    }
}
