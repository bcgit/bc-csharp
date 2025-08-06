using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithID
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ParametersWithID Create<TState>(ICipherParameters parameters, int idLength, TState state,
            System.Buffers.SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (idLength < 0)
                throw new ArgumentOutOfRangeException(nameof(idLength));

            ParametersWithID result = new ParametersWithID(parameters, idLength);
            action(result.m_id, state);
            return result;
        }
#endif

        internal static ICipherParameters ApplyOptionalID(ICipherParameters parameters, byte[] id) =>
            id == null ? parameters : new ParametersWithIV(parameters, id);

        private readonly ICipherParameters m_parameters;
        private readonly byte[] m_id;

        public ParametersWithID(ICipherParameters parameters, byte[] id)
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

        private ParametersWithID(ICipherParameters parameters, int idLength)
        {
            if (idLength < 0)
                throw new ArgumentOutOfRangeException(nameof(idLength));

            // NOTE: 'parameters' may be null to imply key re-use
            m_parameters = parameters;
            m_id = new byte[idLength];
        }

        public void CopyIDTo(byte[] buf, int off, int len)
        {
            if (m_id.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            Array.Copy(m_id, 0, buf, off, len);
        }

        public byte[] GetID() => (byte[])m_id.Clone();

        public int IDLength => m_id.Length;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalID => m_id;
#endif

        public ICipherParameters Parameters => m_parameters;
    }
}
