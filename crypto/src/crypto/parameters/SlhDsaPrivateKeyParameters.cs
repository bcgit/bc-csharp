using System;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPrivateKeyParameters
        : SlhDsaKeyParameters
    {
        private readonly SK m_sk;
        private readonly PK m_pk;

        public SlhDsaPrivateKeyParameters(SlhDsaParameters parameters, byte[] encoding)
            : base(true, parameters)
        {
            int n = parameters.N;
            if (encoding.Length != 4 * n)
                throw new ArgumentException("private key encoding does not match parameters", nameof(encoding));

            m_sk = new SK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
            m_pk = new PK(Arrays.CopyOfRange(encoding, 2 * n, 3 * n), Arrays.CopyOfRange(encoding, 3 * n, 4 * n));
        }

        internal SlhDsaPrivateKeyParameters(SlhDsaParameters parameters, byte[] skSeed, byte[] prf,
            byte[] pkSeed, byte[] pkRoot)
            : base(true, parameters)
        {
            m_sk = new SK(skSeed, prf);
            m_pk = new PK(pkSeed, pkRoot);
        }

        internal SlhDsaPrivateKeyParameters(SlhDsaParameters parameters, SK sk, PK pk)
            : base(true, parameters)
        {
            m_sk = sk;
            m_pk = pk;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_sk.seed, m_sk.prf, m_pk.seed, m_pk.root);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_pk.seed, m_pk.root);

        internal PK PK => m_pk;

        internal SK SK => m_sk;
    }
}
