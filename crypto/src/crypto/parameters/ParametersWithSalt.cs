using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include a salt value.
    /// </summary>
    public class ParametersWithSalt
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Create a new <see cref="ParametersWithSalt"/> instance using a span action.
        /// </summary>
        /// <typeparam name="TState">The type of the state object.</typeparam>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="saltLength">The length of the salt in bytes.</param>
        /// <param name="state">The state object for the action.</param>
        /// <param name="action">The action to initialize the salt.</param>
        /// <returns>A new <see cref="ParametersWithSalt"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="action"/> is null.</exception>
        public static ParametersWithSalt Create<TState>(ICipherParameters parameters, int saltLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            ParametersWithSalt result = new ParametersWithSalt(parameters, saltLength);
            action(result.m_salt, state);
            return result;
        }
#endif

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_salt;

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="salt">The salt bytes.</param>
        public ParametersWithSalt(ICipherParameters parameters, byte[] salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CopyBuffer(salt);
        }

        /// <summary>
        /// Constructor with offset and length for salt.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="salt">The salt byte array.</param>
        /// <param name="saltOff">The offset into the salt array.</param>
        /// <param name="saltLen">The length of the salt to use.</param>
        public ParametersWithSalt(ICipherParameters parameters, byte[] salt, int saltOff, int saltLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CopySegment(salt, saltOff, saltLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Constructor using Span for salt.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="salt">The salt span.</param>
        public ParametersWithSalt(ICipherParameters parameters, ReadOnlySpan<byte> salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = salt.ToArray();
        }

        /// <summary>
        /// Initialise the salt with a given length.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="saltLength">The length of the salt in bytes.</param>
        private ParametersWithSalt(ICipherParameters parameters, int saltLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CreateBuffer<byte>(saltLength);
        }
#endif

        /// <summary>
        /// Copy the salt into a segment of a destination buffer.
        /// </summary>
        /// <param name="buf">The destination buffer.</param>
        /// <param name="off">The offset into the destination buffer.</param>
        /// <param name="len">The length to copy.</param>
        public void CopySaltTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_salt, buf, off, len);

        /// <summary>
        /// Return a copy of the salt.
        /// </summary>
        /// <returns>A new array containing the salt bytes.</returns>
        public byte[] GetSalt() => Arrays.InternalCopyBuffer(m_salt);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Allows internal access to the salt as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        internal ReadOnlySpan<byte> InternalSalt => m_salt;
#endif

        /// <summary>
        /// Return the base parameters associated with this salt.
        /// </summary>
        /// <returns>The parameters wrapped by this salt.</returns>
        public ICipherParameters Parameters => m_parameters;

        /// <summary>
        /// Return the length of the salt in bytes.
        /// </summary>
        /// <returns>The length of the salt in bytes.</returns>
        public int SaltLength => m_salt.Length;
    }
}
