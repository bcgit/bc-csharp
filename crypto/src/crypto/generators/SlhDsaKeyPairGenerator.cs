using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.SlhDsa;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    /// <summary>
    /// Key-pair generator for SLH-DSA (FIPS 205). Driven by an <see cref="SlhDsaKeyGenerationParameters"/>
    /// init payload; produces an <see cref="AsymmetricCipherKeyPair"/> bound to the chosen parameter set.
    /// </summary>
    public sealed class SlhDsaKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom m_random;
        private SlhDsaParameters m_parameters;

        /// <summary>
        /// Initialise with an <see cref="SlhDsaKeyGenerationParameters"/> instance; the <see cref="SecureRandom"/>
        /// and parameter set are taken from it.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="SlhDsaKeyGenerationParameters"/>.</exception>
        public void Init(KeyGenerationParameters parameters)
        {
            m_random = parameters.Random;
            m_parameters = ((SlhDsaKeyGenerationParameters)parameters).Parameters;
        }

        /// <summary>
        /// Generate a fresh SLH-DSA key pair by drawing the three <c>n</c>-byte seeds
        /// (<c>SK.seed</c>, <c>SK.prf</c>, <c>PK.seed</c>) and computing the hypertree root.
        /// </summary>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var engine = m_parameters.ParameterSet.GetEngine();

            byte[] skSeed = SecRand(engine.N);
            byte[] skPrf = SecRand(engine.N);
            byte[] pkSeed = SecRand(engine.N);

            SK sk = new SK(skSeed, skPrf);

            engine.Init(pkSeed);

            // TODO
            PK pk = new PK(pkSeed, new HT(engine, sk.Seed, pkSeed).HTPubKey);

            return new AsymmetricCipherKeyPair(
                new SlhDsaPublicKeyParameters(m_parameters, pk),
                new SlhDsaPrivateKeyParameters(m_parameters, sk, pk));
        }

        private byte[] SecRand(int n) => SecureRandom.GetNextBytes(m_random, n);
    }
}
