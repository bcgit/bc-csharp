using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    [Obsolete("Use SLH-DSA instead")]
    public sealed class SphincsPlusPrivateKeyParameters
        : SphincsPlusKeyParameters
    {
        internal readonly SK m_sk;
        internal readonly PK m_pk;

        public SphincsPlusPrivateKeyParameters(SphincsPlusParameters parameters, byte[] skpkEncoded)
            : base(true, parameters)
        {
            int n = parameters.N;
            if (skpkEncoded.Length != 4 * n)
                throw new ArgumentException("private key encoding does not match parameters");

            m_sk = new SK(Arrays.CopyOfRange(skpkEncoded, 0, n), Arrays.CopyOfRange(skpkEncoded, n, 2 * n));
            m_pk = new PK(Arrays.CopyOfRange(skpkEncoded, 2 * n, 3 * n), Arrays.CopyOfRange(skpkEncoded, 3 * n, 4 * n));
        }

        public SphincsPlusPrivateKeyParameters(SphincsPlusParameters parameters, byte[] skSeed, byte[] prf,
            byte[] pkSeed, byte[] pkRoot)
            : base(true, parameters)
        {
            m_sk = new SK(skSeed, prf);
            m_pk = new PK(pkSeed, pkRoot);
        }

        internal SphincsPlusPrivateKeyParameters(SphincsPlusParameters parameters, SK sk, PK pk)
            : base(true, parameters)
        {
            m_sk = sk;
            m_pk = pk;
        }

        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(m_sk.seed, m_sk.prf, m_pk.seed, m_pk.root);
        }

        public byte[] GetEncodedPublicKey()
        {
            return Arrays.ConcatenateAll(m_pk.seed, m_pk.root);
        }

        public byte[] GetPrf()
        {
            return Arrays.Clone(m_sk.prf);
        }

        public byte[] GetPublicKey()
        {
            return Arrays.Concatenate(m_pk.seed, m_pk.root);
        }

        public byte[] GetPublicSeed()
        {
            return Arrays.Clone(m_pk.seed);
        }

        public byte[] GetRoot()
        {
            return Arrays.Clone(m_pk.root);
        }

        public byte[] GetSeed()
        {
            return Arrays.Clone(m_sk.seed);
        }

        internal PK PK => m_pk;

        internal SK SK => m_sk;
    }
}
