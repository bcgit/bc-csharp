using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>The base class for symmetric, or secret, cipher key generators.</summary>
    public class CipherKeyGenerator
    {
        protected internal SecureRandom random;
        protected internal int strength;

        private bool m_uninitialised = true;
        private int m_defaultStrength;

        public CipherKeyGenerator()
        {
        }

        internal CipherKeyGenerator(int defaultStrength)
        {
            if (defaultStrength < 1)
                throw new ArgumentException("strength must be a positive value", nameof(defaultStrength));

            m_defaultStrength = defaultStrength;
        }

        public int DefaultStrength => m_defaultStrength;

        /// <summary>Initialise the key generator.</summary>
        /// <param name="parameters">The parameters to be used for key generation</param>
        public void Init(KeyGenerationParameters parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            m_uninitialised = false;

            EngineInit(parameters);
        }

        protected virtual void EngineInit(KeyGenerationParameters parameters)
        {
            this.random = parameters.Random;
            this.strength = (parameters.Strength + 7) / 8;
        }

        /// <summary>Generate a secret key.</summary>
        /// <returns>A byte array containing the key value.</returns>
        public byte[] GenerateKey()
        {
            EnsureInitialized();

            return EngineGenerateKey();
        }

        public KeyParameter GenerateKeyParameter()
        {
            EnsureInitialized();

            return EngineGenerateKeyParameter();
        }

        protected virtual byte[] EngineGenerateKey() => SecureRandom.GetNextBytes(random, strength);

        protected virtual KeyParameter EngineGenerateKeyParameter()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            // TODO[api] Redesign to avoid this exceptional case
            // Avoid problems if EngineGenerateKey() was overridden before this method even existed.
            if (GetType() == typeof(CipherKeyGenerator))
            {
                return KeyParameter.Create(strength, random, (bytes, random) =>
                {
                    random.NextBytes(bytes);
                });
            }
#endif

            return new KeyParameter(EngineGenerateKey());
        }

        protected virtual void EnsureInitialized()
        {
            if (m_uninitialised)
            {
                if (m_defaultStrength < 1)
                    throw new InvalidOperationException("Generator has not been initialised");

                m_uninitialised = false;

                EngineInit(new KeyGenerationParameters(CryptoServicesRegistrar.GetSecureRandom(), m_defaultStrength));
            }
        }
    }
}
