using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * a ElGamal key pair generator.
     * <p>
     * This Generates keys consistent for use with ElGamal as described in
     * page 164 of "Handbook of Applied Cryptography".</p>
     */
    // TODO[api] sealed
    public class ElGamalKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private ElGamalKeyGenerationParameters m_parameters;

        public void Init(KeyGenerationParameters parameters)
        {
            var elGamalParameters = (ElGamalKeyGenerationParameters)parameters;

            ElGamalParameters egp = elGamalParameters.Parameters;
            DHKeyGeneratorHelper.CheckPrivateValueLength(egp.P, egp.L, nameof(parameters));

            m_parameters = elGamalParameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            ElGamalParameters egp = m_parameters.Parameters;
            DHParameters dhp = new DHParameters(egp.P, egp.G, null, 0, egp.L);

            DHKeyGeneratorHelper.CalculateKeyPair(dhp, m_parameters.Random, out BigInteger x, out BigInteger y);

            return new AsymmetricCipherKeyPair(
                new ElGamalPublicKeyParameters(y, egp),
                new ElGamalPrivateKeyParameters(x, egp));
        }
    }
}
