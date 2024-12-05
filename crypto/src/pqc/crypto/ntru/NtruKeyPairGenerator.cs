using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    public class NtruKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private NtruKeyGenerationParameters m_keyGenParameters;
        private SecureRandom m_random;

        public void Init(KeyGenerationParameters parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            m_keyGenParameters = (NtruKeyGenerationParameters)parameters;
            m_random = parameters.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var parameters = m_keyGenParameters.NtruParameters;
            var parameterSet = parameters.ParameterSet;

            var seed = SecureRandom.GetNextBytes(m_random, parameterSet.SampleFgBytes());

            NtruOwcpa owcpa = new NtruOwcpa(parameterSet);
            OwcpaKeyPair owcpaKeys = owcpa.KeyPair(seed);

            byte[] publicKey = owcpaKeys.PublicKey;

            byte[] privateKey = Arrays.CopyOf(owcpaKeys.PrivateKey, parameterSet.NtruSecretKeyBytes());
            m_random.NextBytes(privateKey, parameterSet.OwcpaSecretKeyBytes(), parameterSet.PrfKeyBytes);

#pragma warning disable CS0618 // Type or member is obsolete
            return new AsymmetricCipherKeyPair(
                new NtruPublicKeyParameters(parameters, publicKey),
                new NtruPrivateKeyParameters(parameters, privateKey));
#pragma warning restore CS0618 // Type or member is obsolete
        }
    }
}
