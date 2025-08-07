using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary> Cipher parameters with a fixed salt value associated with them.</summary>
    public class ParametersWithSalt
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
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

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CopyBuffer(salt);
        }

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt, int saltOff, int saltLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CopySegment(salt, saltOff, saltLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithSalt(ICipherParameters parameters, ReadOnlySpan<byte> salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = salt.ToArray();
        }
#endif

        private ParametersWithSalt(ICipherParameters parameters, int saltLength)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = Arrays.CreateBuffer<byte>(saltLength);
        }

        public void CopySaltTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_salt, buf, off, len);

        public byte[] GetSalt() => Arrays.InternalCopyBuffer(m_salt);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalSalt => m_salt;
#endif

        public ICipherParameters Parameters => m_parameters;

        public int SaltLength => m_salt.Length;
    }
}
