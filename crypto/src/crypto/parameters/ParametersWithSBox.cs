using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include a substitution box (S-Box).
    /// </summary>
    public class ParametersWithSBox
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Create a new <see cref="ParametersWithSBox"/> instance using a span action.
        /// </summary>
        /// <typeparam name="TState">The type of the state object.</typeparam>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="sBoxLength">The length of the S-Box in bytes.</param>
        /// <param name="state">The state object for the action.</param>
        /// <param name="action">The action to initialize the S-Box.</param>
        /// <returns>A new <see cref="ParametersWithSBox"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="action"/> is null.</exception>
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

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="sBox">The S-Box bytes.</param>
        public ParametersWithSBox(ICipherParameters parameters, byte[] sBox)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CopyBuffer(sBox);
        }

        /// <summary>
        /// Constructor with offset and length for S-Box.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="sBox">The S-Box byte array.</param>
        /// <param name="sBoxOff">The offset into the S-Box array.</param>
        /// <param name="sBoxLen">The length of the S-Box to use.</param>
        public ParametersWithSBox(ICipherParameters parameters, byte[] sBox, int sBoxOff, int sBoxLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CopySegment(sBox, sBoxOff, sBoxLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Constructor using Span for S-Box.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="sBox">The S-Box span.</param>
        public ParametersWithSBox(ICipherParameters parameters, ReadOnlySpan<byte> sBox)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = sBox.ToArray();
        }

        /// <summary>
        /// Initialise the S-Box with a given length.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="sBoxLength">The length of the S-Box in bytes.</param>
        private ParametersWithSBox(ICipherParameters parameters, int sBoxLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_sBox = Arrays.CreateBuffer<byte>(sBoxLength);
        }
#endif

        /// <summary>
        /// Copy the S-Box into a segment of a destination buffer.
        /// </summary>
        /// <param name="buf">The destination buffer.</param>
        /// <param name="off">The offset into the destination buffer.</param>
        /// <param name="len">The length to copy.</param>
        public void CopySBoxTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_sBox, buf, off, len);

        /// <summary>
        /// Return a copy of the S-Box.
        /// </summary>
        /// <returns>A new array containing the S-Box bytes.</returns>
        public byte[] GetSBox() => Arrays.InternalCopyBuffer(m_sBox);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Allows internal access to the S-Box as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        internal ReadOnlySpan<byte> InternalSBox => m_sBox;
#endif

        /// <summary>
        /// Return the base parameters associated with this S-Box.
        /// </summary>
        /// <returns>The parameters wrapped by this S-Box.</returns>
        public ICipherParameters Parameters => m_parameters;

        /// <summary>
        /// Return the length of the S-Box in bytes.
        /// </summary>
        /// <returns>The length of the S-Box in bytes.</returns>
        public int SBoxLength => m_sBox.Length;
    }
}
