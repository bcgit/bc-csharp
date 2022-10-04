using System;

using Org.BouncyCastle.Utilities;

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
        }

        public ParametersWithID(ICipherParameters parameters, byte[] id, int idOff, int idLen)
        {
            m_parameters = parameters;
            m_id = Arrays.CopyOfRange(id, idOff, idOff + idLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ParametersWithID(ICipherParameters parameters, ReadOnlySpan<byte> id)
        {
            m_parameters = parameters;
            m_id = id.ToArray();
        }
#endif

        public byte[] GetID()
        {
            return m_id;
        }

        public ICipherParameters Parameters => m_parameters;
    }
}
