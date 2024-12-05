using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemPrivateKeyParameters
        : MLKemKeyParameters
    {
        public static MLKemPrivateKeyParameters FromEncoding(MLKemParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            var engine = parameters.ParameterSet.GetEngine(random: null);

            int index = 0;

            byte[] s = Arrays.CopyOfRange(encoding, 0, engine.IndCpaSecretKeyBytes);
            index += engine.IndCpaSecretKeyBytes;

            byte[] t = Arrays.CopyOfRange(encoding, index, index + engine.IndCpaPublicKeyBytes - MLKemEngine.SymBytes);
            index += engine.IndCpaPublicKeyBytes - MLKemEngine.SymBytes;

            byte[] rho = Arrays.CopyOfRange(encoding, index, index + 32);
            index += 32;

            byte[] hpk = Arrays.CopyOfRange(encoding, index, index + 32);
            index += 32;

            byte[] nonce = Arrays.CopyOfRange(encoding, index, index + MLKemEngine.SymBytes);
            //index += MLKemEngine.SymBytes;

            byte[] seed = null;

            return new MLKemPrivateKeyParameters(parameters, s, hpk, nonce, t, rho, seed);
        }

        public static MLKemPrivateKeyParameters FromSeed(MLKemParameters parameters, byte[] seed)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (seed == null)
                throw new ArgumentNullException(nameof(seed));
            if (seed.Length != parameters.ParameterSet.SeedLength)
                throw new ArgumentException("invalid seed", nameof(seed));

            var engine = parameters.ParameterSet.GetEngine(random: null);

            byte[] d = Arrays.CopyOfRange(seed, 0, MLKemEngine.SymBytes);
            byte[] z = Arrays.CopyOfRange(seed, MLKemEngine.SymBytes, seed.Length);

            engine.GenerateKemKeyPairInternal(d, z, out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk,
                out byte[] nonce, out byte[] seed2);

            return new MLKemPrivateKeyParameters(parameters, s, hpk, nonce, t, rho, seed2);
        }

        internal readonly byte[] m_s;
        internal readonly byte[] m_hpk;
        internal readonly byte[] m_nonce;
        internal readonly byte[] m_t;
        internal readonly byte[] m_rho;
        internal readonly byte[] m_seed;

        internal MLKemPrivateKeyParameters(MLKemParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t,
            byte[] rho, byte[] seed)
            : base(true, parameters)
        {
            m_s = s;
            m_hpk = hpk;
            m_nonce = nonce;
            m_t = t;
            m_rho = rho;
            m_seed = seed;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_s, m_t, m_rho, m_hpk, m_nonce);

        public MLKemPublicKeyParameters GetPublicKey() => new MLKemPublicKeyParameters(Parameters, m_t, m_rho);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_t, m_rho);

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        internal byte[] Seed => m_seed;
    }
}
