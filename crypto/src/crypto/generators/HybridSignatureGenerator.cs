using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.crypto.generators
{
    public class HybridSignatureGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private HybridKeyGenerationParameters parameters;

        private SecureRandom random;

        public void Init(KeyGenerationParameters parameters)
        {
            if (!(parameters is HybridKeyGenerationParameters))
            {
                throw new ArgumentException("Provided parameter is not hybrid parameter");
            }

            this.parameters = parameters as HybridKeyGenerationParameters;
            this.random = this.parameters.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            AsymmetricCipherKeyPair classicalKeypair = null;
            if (parameters.ClassicalParameters is ECKeyGenerationParameters)
            {
                var generator = new ECKeyPairGenerator("ECDSA");
                generator.Init(parameters.ClassicalParameters);
                classicalKeypair = generator.GenerateKeyPair();
            }
            else if (parameters.ClassicalParameters is RsaKeyGenerationParameters)
            {
                // TODO
                throw new NotImplementedException("Rsa hybrid keypair generation not supported");
            }

            if (classicalKeypair == null)
            {
                throw new Exception("Classical parameter not supported");
            }

            AsymmetricCipherKeyPair postQuantumKeypair = null;
            if (parameters.PostQuantumParameters is DilithiumKeyGenerationParameters)
            {
                var generator = new DilithiumKeyPairGenerator();
                generator.Init(parameters.PostQuantumParameters);
                postQuantumKeypair = generator.GenerateKeyPair();
            }
            else if (parameters.PostQuantumParameters is SphincsPlusKeyGenerationParameters)
            {
                var generator = new SphincsPlusKeyPairGenerator();
                generator.Init(parameters.PostQuantumParameters);
                postQuantumKeypair = generator.GenerateKeyPair();
            }

            if (postQuantumKeypair == null)
            {
                throw new Exception("Post-quantum parameter not supported");
            }

            return new AsymmetricCipherKeyPair(new HybridKeyParameters(classicalKeypair.Public, postQuantumKeypair.Public), new HybridKeyParameters(classicalKeypair.Private, postQuantumKeypair.Private));
        }

        public static byte[] GenerateSignature(AsymmetricKeyParameter privKey, byte[] message)
        {
            // FIXME(bence)
        }

        public static bool VerifySignature(AsymmetricKeyParameter pubKey, byte[] message, byte[] signature)
        {
            // FIXME(bence)
        }
    }
}
