using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{

    /// <summary> Cipher parameters with a fixed salt value associated with them.</summary>
    public class ParametersWithSalt
        : ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_salt;

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt)
            : this(parameters, salt, 0, salt.Length)
        {
        }

        public ParametersWithSalt(ICipherParameters parameters, byte[] salt, int saltOff, int saltLen)
        {
            m_parameters = parameters;
            m_salt = Arrays.CopyOfRange(salt, saltOff, saltOff + saltLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithSalt(ICipherParameters parameters, ReadOnlySpan<byte> salt)
        {
            m_parameters = parameters;
            m_salt = salt.ToArray();
        }
#endif

        public byte[] GetSalt()
        {
            return m_salt;
        }

        public ICipherParameters Parameters => m_parameters;
    }
}
