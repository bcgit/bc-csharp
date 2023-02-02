using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithIV
        : ICipherParameters
    {
        internal static ICipherParameters ApplyOptionalIV(ICipherParameters parameters, byte[] iv)
        {
            return iv == null ? parameters : new ParametersWithIV(parameters, iv);
        }

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_iv;

        public ParametersWithIV(ICipherParameters parameters, byte[] iv)
            : this(parameters, iv, 0, iv.Length)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            m_parameters = parameters;
            m_iv = (byte[])iv.Clone();
        }

        public ParametersWithIV(ICipherParameters parameters, byte[] iv, int ivOff, int ivLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            m_parameters = parameters;
            m_iv = new byte[ivLen];
            Array.Copy(iv, ivOff, m_iv, 0, ivLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithIV(ICipherParameters parameters, ReadOnlySpan<byte> iv)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_iv = iv.ToArray();
        }
#endif

        public byte[] GetIV()
        {
            return (byte[])m_iv.Clone();
        }

        public ICipherParameters Parameters => m_parameters;
    }
}
