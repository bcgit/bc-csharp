using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include an Identity (ID).
    /// </summary>
    public class ParametersWithID
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Create a new <see cref="ParametersWithID"/> instance using a span action.
        /// </summary>
        /// <typeparam name="TState">The type of the state object.</typeparam>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="idLength">The length of the ID in bytes.</param>
        /// <param name="state">The state object for the action.</param>
        /// <param name="action">The action to initialize the ID.</param>
        /// <returns>A new <see cref="ParametersWithID"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="action"/> is null.</exception>
        public static ParametersWithID Create<TState>(ICipherParameters parameters, int idLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithID result = new ParametersWithID(parameters, idLength);
            action(result.m_id, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_id;

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="id">The identity bytes.</param>
        public ParametersWithID(ICipherParameters parameters, byte[] id)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = Arrays.CopyBuffer(id);
        }

        /// <summary>
        /// Constructor with offset and length for ID.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="id">The identity byte array.</param>
        /// <param name="idOff">The offset into the ID array.</param>
        /// <param name="idLen">The length of the ID to use.</param>
        public ParametersWithID(ICipherParameters parameters, byte[] id, int idOff, int idLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = Arrays.CopySegment(id, idOff, idLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Constructor using Span for ID.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="id">The identity span.</param>
        public ParametersWithID(ICipherParameters parameters, ReadOnlySpan<byte> id)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = id.ToArray();
        }

        /// <summary>
        /// Initialise the ID with a given length.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="idLength">The length of the ID in bytes.</param>
        private ParametersWithID(ICipherParameters parameters, int idLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = Arrays.CreateBuffer<byte>(idLength);
        }
#endif

        /// <summary>
        /// Copy the ID into a segment of a destination buffer.
        /// </summary>
        /// <param name="buf">The destination buffer.</param>
        /// <param name="off">The offset into the destination buffer.</param>
        /// <param name="len">The length to copy.</param>
        public void CopyIDTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_id, buf, off, len);

        /// <summary>
        /// Return a copy of the ID.
        /// </summary>
        /// <returns>A new array containing the ID bytes.</returns>
        public byte[] GetID() => Arrays.InternalCopyBuffer(m_id);

        /// <summary>
        /// Return the length of the ID in bytes.
        /// </summary>
        /// <returns>The length of the ID in bytes.</returns>
        public int IDLength => m_id.Length;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Allows internal access to the ID as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        internal ReadOnlySpan<byte> InternalID => m_id;
#endif

        /// <summary>
        /// Return the base parameters associated with this ID.
        /// </summary>
        /// <returns>The parameters wrapped by this ID.</returns>
        public ICipherParameters Parameters => m_parameters;
    }
}
