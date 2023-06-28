using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithID
        : ICipherParameters
    {
        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_id;

        public ParametersWithID(ICipherParameters parameters, byte[] id)
            : this(parameters, id, 0, id.Length)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            m_parameters = parameters;
            m_id = (byte[])id.Clone();
        }

        public ParametersWithID(ICipherParameters parameters, byte[] id, int idOff, int idLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            m_parameters = parameters;
            m_id = new byte[idLen];
            Array.Copy(id, idOff, m_id, 0, idLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithID(ICipherParameters parameters, ReadOnlySpan<byte> id)
        {
            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = id.ToArray();
        }
#endif

        public byte[] GetID()
        {
            return (byte[])m_id.Clone();
        }

        public ICipherParameters Parameters => m_parameters;
    }
}
