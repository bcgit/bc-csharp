using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * a Diffie-Hellman key pair generator.
     *
     * This generates keys consistent for use in the MTI/A0 key agreement protocol
     * as described in "Handbook of Applied Cryptography", Pages 516-519.
     */
    // TODO[api] sealed
    public class DHKeyPairGenerator
		: IAsymmetricCipherKeyPairGenerator
    {
		private DHKeyGenerationParameters m_parameters;

		public virtual void Init(KeyGenerationParameters parameters)
        {
            m_parameters = (DHKeyGenerationParameters)parameters;
        }

		public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
			DHParameters dhp = m_parameters.Parameters;

			BigInteger x = DHKeyGeneratorHelper.CalculatePrivate(dhp, m_parameters.Random);
			BigInteger y = DHKeyGeneratorHelper.CalculatePublic(dhp, x);

			return new AsymmetricCipherKeyPair(
                new DHPublicKeyParameters(y, dhp),
                new DHPrivateKeyParameters(x, dhp));
        }
    }
}
