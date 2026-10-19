using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    [Obsolete("Use SLH-DSA instead")]
    public sealed class SphincsPlusPublicKeyParameters
        : SphincsPlusKeyParameters
    {
        private readonly PK m_pk;

        /// <summary>Create a new <see cref="SphincsPlusPublicKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="pkEncoded">The pk encoded.</param>
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

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(m_pk.seed, m_pk.root);
        }

        /// <summary>Return the root.</summary>
        public byte[] GetRoot()
        {
            return Arrays.Clone(m_pk.root);
        }

        /// <summary>Return the seed.</summary>
        public byte[] GetSeed()
        {
            return Arrays.Clone(m_pk.seed);
        }

        internal PK PK => m_pk;
    }
}
