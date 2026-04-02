using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Wrapper class for parameters which include User Key Material (UKM).
    /// </summary>
    public class ParametersWithUkm
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Create a new <see cref="ParametersWithUkm"/> instance using a span action.
        /// </summary>
        /// <typeparam name="TState">The type of the state object.</typeparam>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="ukmLength">The length of the UKM in bytes.</param>
        /// <param name="state">The state object for the action.</param>
        /// <param name="action">The action to initialize the UKM.</param>
        /// <returns>A new <see cref="ParametersWithUkm"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="action"/> is null.</exception>
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

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="ukm">The UKM bytes.</param>
        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CopyBuffer(ukm);
        }

        /// <summary>
        /// Constructor with offset and length for UKM.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="ukm">The UKM byte array.</param>
        /// <param name="ukmOff">The offset into the UKM array.</param>
        /// <param name="ukmLen">The length of the UKM to use.</param>
        public ParametersWithUkm(ICipherParameters parameters, byte[] ukm, int ukmOff, int ukmLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CopySegment(ukm, ukmOff, ukmLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Constructor using Span for UKM.
        /// </summary>
        /// <param name="parameters">The base parameters (may be null for key reuse).</param>
        /// <param name="ukm">The UKM span.</param>
        public ParametersWithUkm(ICipherParameters parameters, ReadOnlySpan<byte> ukm)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = ukm.ToArray();
        }

        /// <summary>
        /// Initialise the UKM with a given length.
        /// </summary>
        /// <param name="parameters">The base parameters.</param>
        /// <param name="ukmLength">The length of the UKM in bytes.</param>
        private ParametersWithUkm(ICipherParameters parameters, int ukmLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_ukm = Arrays.CreateBuffer<byte>(ukmLength);
        }
#endif

        /// <summary>
        /// Copy the UKM into a segment of a destination buffer.
        /// </summary>
        /// <param name="buf">The destination buffer.</param>
        /// <param name="off">The offset into the destination buffer.</param>
        /// <param name="len">The length to copy.</param>
        public void CopyUkmTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_ukm, buf, off, len);

        /// <summary>
        /// Return a copy of the UKM.
        /// </summary>
        /// <returns>A new array containing the UKM bytes.</returns>
        public byte[] GetUkm() => Arrays.InternalCopyBuffer(m_ukm);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Allows internal access to the UKM as a <see cref="ReadOnlySpan{T}"/>.
        /// </summary>
        internal ReadOnlySpan<byte> InternalUkm => m_ukm;
#endif

        /// <summary>
        /// Return the base parameters associated with this UKM.
        /// </summary>
        /// <returns>The parameters wrapped by this UKM.</returns>
        public ICipherParameters Parameters => m_parameters;

        /// <summary>
        /// Return the length of the UKM in bytes.
        /// </summary>
        /// <returns>The length of the UKM in bytes.</returns>
        public int UkmLength => m_ukm.Length;
    }
}
