using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    public sealed class SphincsPlusPublicKeyParameters
        : SphincsPlusKeyParameters
    {
        private readonly PK m_pk;

        public SphincsPlusPublicKeyParameters(SphincsPlusParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            int n = parameters.N;
            if (pkEncoded.Length != 2 * n)
                throw new ArgumentException("public key encoding does not match parameters", nameof(pkEncoded));

            m_pk = new PK(Arrays.CopyOfRange(pkEncoded, 0, n), Arrays.CopyOfRange(pkEncoded, n, 2 * n));
        }

        internal SphincsPlusPublicKeyParameters(SphincsPlusParameters parameters, PK pk)
            : base(false, parameters)
        {
            m_pk = pk;
        }

        public byte[] GetSeed()
        {
            return Arrays.Clone(m_pk.seed);
        }

        public byte[] GetRoot()
        {
            return Arrays.Clone(m_pk.root);
        }

        public byte[] GetEncoded()
        {
            var id = Pack.UInt32_To_BE((uint)SphincsPlusParameters.GetID(Parameters));
            return Arrays.ConcatenateAll(id, m_pk.seed, m_pk.root);
        }
    }
}
