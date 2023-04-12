using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /**
	 * The base class for symmetric, or secret, cipher key generators.
	 */
    public class CipherKeyGenerator
	{
		protected internal SecureRandom	random;
		protected internal int			strength;
		private bool uninitialised = true;
		private int defaultStrength;

		public CipherKeyGenerator()
		{
		}

		internal CipherKeyGenerator(
			int defaultStrength)
		{
			if (defaultStrength < 1)
				throw new ArgumentException("strength must be a positive value", "defaultStrength");

			this.defaultStrength = defaultStrength;
		}

		public int DefaultStrength
		{
			get { return defaultStrength; }
		}

		/**
		 * initialise the key generator.
		 *
		 * @param param the parameters to be used for key generation
		 */
		public void Init(KeyGenerationParameters parameters)
		{
			if (parameters == null)
				throw new ArgumentNullException(nameof(parameters));

			this.uninitialised = false;

			EngineInit(parameters);
		}

		protected virtual void EngineInit(KeyGenerationParameters parameters)
		{
			this.random = parameters.Random;
			this.strength = (parameters.Strength + 7) / 8;
		}

		/**
		 * Generate a secret key.
		 *
		 * @return a byte array containing the key value.
		 */
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

        protected virtual byte[] EngineGenerateKey()
		{
            return SecureRandom.GetNextBytes(random, strength);
		}

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
            if (uninitialised)
            {
                if (defaultStrength < 1)
                    throw new InvalidOperationException("Generator has not been initialised");

                uninitialised = false;

                EngineInit(new KeyGenerationParameters(CryptoServicesRegistrar.GetSecureRandom(), defaultStrength));
            }
        }
    }
}
