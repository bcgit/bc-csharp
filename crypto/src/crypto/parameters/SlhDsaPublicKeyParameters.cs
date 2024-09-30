using System;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPublicKeyParameters
        : SlhDsaKeyParameters
    {
        private readonly PK m_pk;

        public SlhDsaPublicKeyParameters(SlhDsaParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            int n = parameters.N;
            if (encoding.Length != 2 * n)
                throw new ArgumentException("public key encoding does not match parameters", nameof(encoding));

            m_pk = new PK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
        }

        internal SlhDsaPublicKeyParameters(SlhDsaParameters parameters, PK pk)
            : base(false, parameters)
        {
            m_pk = pk;
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_pk.seed, m_pk.root);

        internal PK PK => m_pk;
    }
}
