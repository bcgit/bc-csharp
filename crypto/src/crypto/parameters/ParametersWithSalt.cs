using System;

namespace Org.BouncyCastle.Crypto.Parameters
{

    /// <summary> Cipher parameters with a fixed salt value associated with them.</summary>
    public class ParametersWithSalt
        : ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_salt;

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));

            m_parameters = parameters;
            m_salt = (byte[])salt.Clone();
        }

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt, int saltOff, int saltLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));

            m_parameters = parameters;
            m_salt = new byte[saltLen];
            Array.Copy(salt, saltOff, m_salt, 0, saltLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithSalt(ICipherParameters parameters, ReadOnlySpan<byte> salt)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_salt = salt.ToArray();
        }
#endif

        public byte[] GetSalt()
        {
            return (byte[])m_salt.Clone();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalSalt => m_salt;
#endif

        public ICipherParameters Parameters => m_parameters;

        public int SaltLength => m_salt.Length;
    }
}
