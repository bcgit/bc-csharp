using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>The base class for symmetric, or secret, cipher key generators.</summary>
    public class CipherKeyGenerator
    {
        /// <summary>The source of randomness.</summary>
        protected internal SecureRandom random;
        /// <summary>The strength of the key to generate, in bytes.</summary>
        protected internal int strength;

        private bool m_uninitialised = true;
        private int m_defaultStrength;

        /// <summary>Create a new <see cref="CipherKeyGenerator"/>.</summary>
        public CipherKeyGenerator()
        {
        }

        internal CipherKeyGenerator(int defaultStrength)
        {
            if (defaultStrength < 1)
                throw new ArgumentException("strength must be a positive value", nameof(defaultStrength));

            m_defaultStrength = defaultStrength;
        }

        /// <summary>Gets the default strength.</summary>
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

        /// <summary>Initialise the generator from the key generation parameters.</summary>
        /// <param name="parameters">The key generation parameters.</param>
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

        /// <summary>Generate a secret key.</summary>
        /// <returns>A <see cref="KeyParameter"/> holding the key.</returns>
        public KeyParameter GenerateKeyParameter()
        {
            EnsureInitialized();

            return EngineGenerateKeyParameter();
        }

        /// <summary>Generate the bytes of a secret key.</summary>
        /// <returns>A byte array holding the key value.</returns>
        protected virtual byte[] EngineGenerateKey() => SecureRandom.GetNextBytes(random, strength);

        /// <summary>Generate a secret key as key parameters.</summary>
        /// <returns>A <see cref="KeyParameter"/> holding the key.</returns>
        protected virtual KeyParameter EngineGenerateKeyParameter()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            // TODO[api] Redesign to avoid this exceptional case
            // Avoid problems if EngineGenerateKey() was overridden before this method even existed.
            if (GetType() == typeof(CipherKeyGenerator))
            {
                return KeyParameter.Create(strength, random, SecureRandom.Fill);
            }
#endif

            return new KeyParameter(EngineGenerateKey());
        }

        /// <summary>
        /// Ensure that the generator has been initialised, using the default strength if it has not been explicitly.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// The generator has not been initialised and has no default strength.
        /// </exception>
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
