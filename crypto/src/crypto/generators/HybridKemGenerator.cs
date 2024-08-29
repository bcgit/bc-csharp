using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.crypto.generators
{
    public class HybridKemGenerator
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
            this.random = parameters.Random;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            AsymmetricCipherKeyPair classicalKeypair = null;
            if (parameters.ClassicalParameters is ECKeyGenerationParameters)
            {
                var generator = new ECKeyPairGenerator("ECDH");
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
            if (parameters.PostQuantumParameters is KyberKeyGenerationParameters)
            {
                var generator = new KyberKeyPairGenerator();
                generator.Init(parameters.PostQuantumParameters);
                postQuantumKeypair = generator.GenerateKeyPair();
            }

            if (postQuantumKeypair == null)
            {
                throw new Exception("Post-quantum parameter not supported");
            }

            return new AsymmetricCipherKeyPair(new HybridKeyParameters(classicalKeypair.Public, postQuantumKeypair.Public), new HybridKeyParameters(classicalKeypair.Private, postQuantumKeypair.Private));
        }

        public static ISecretWithEncapsulation Encapsulate(AsymmetricKeyParameter pubKey)
        {
            if (!(pubKey is HybridKeyParameters))
            {
                throw new ArgumentException("Provided key parameter is not hybrid");
            }

            var hybridPubKey = pubKey as HybridKeyParameters;

            byte[] classicalCiphertext = null;
            byte[] classicalSharedSecret = null;
            if (hybridPubKey.Classical is ECPublicKeyParameters)
            {
                var generator = new ECKeyPairGenerator("ECDH");
                var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(hybridPubKey.Classical);
                var parameters = new ECKeyGenerationParameters(pubInfo.Algorithm.Algorithm, new SecureRandom());
                generator.Init(parameters);
                var ephemeralKeypair = generator.GenerateKeyPair();

                classicalCiphertext = (ephemeralKeypair.Public as ECPublicKeyParameters).Q.GetEncoded();

                var ecdhAgreement = new ECDHBasicAgreement();
                ecdhAgreement.Init(ephemeralKeypair.Private);
                classicalSharedSecret = ecdhAgreement.CalculateAgreement(hybridPubKey.Classical).ToByteArrayUnsigned();
            }
            else if (hybridPubKey.Classical is RsaKeyParameters)
            {
                // TODO
                throw new NotImplementedException("Rsa hybrid encapsulation not supported");
            }

            if (classicalCiphertext == null || classicalSharedSecret == null)
            {
                throw new Exception("Classical public key not supported");
            }

            byte[] postQuantumCiphertext = null;
            byte[] postQuantumSharedSecret = null;
            if (hybridPubKey.PostQuantum is KyberPublicKeyParameters)
            {
                var encapsulation = new KyberKemGenerator(new SecureRandom()).GenerateEncapsulated(hybridPubKey.PostQuantum);
                postQuantumCiphertext = encapsulation.GetEncapsulation();
                postQuantumSharedSecret = encapsulation.GetSecret();
            }

            if (postQuantumCiphertext == null || postQuantumSharedSecret == null)
            {
                throw new Exception("Post-quantum public key not supported");
            }

            return new SecretWithEncapsulationImpl(Arrays.Concatenate(classicalSharedSecret, postQuantumSharedSecret), Arrays.Concatenate(classicalCiphertext, postQuantumCiphertext));
        }

        public static byte[] Decapsulate(AsymmetricKeyParameter privKey, byte[] ciphertext)
        {
            if (!(privKey is HybridKeyParameters))
            {
                throw new ArgumentException("Provided key parameter is not hybrid");
            }
            if (!privKey.IsPrivate)
            {
                throw new ArgumentException("Provided key is not a private key");
            }

            var hybridPrivKey = privKey as HybridKeyParameters;

            byte[] classicalSharedSecret = null;
            if (hybridPrivKey.Classical is ECPrivateKeyParameters)
            {
                var classical = hybridPrivKey.Classical as ECPrivateKeyParameters;

                // public key is uncompressed ec point
                var publicKeySize = (classical.Parameters.Curve.FieldElementEncodingLength * 2) + 1;

                if (ciphertext.Length <= publicKeySize)
                {
                    throw new Exception("Wrong size classical ciphertext");
                }

                var publicKeyBytes = ciphertext.Take(publicKeySize).ToArray();
                var otherPublicKey = new ECPublicKeyParameters(classical.Parameters.Curve.DecodePoint(publicKeyBytes), classical.Parameters);

                var ecdhAgreement = new ECDHBasicAgreement();
                ecdhAgreement.Init(classical);
                classicalSharedSecret = ecdhAgreement.CalculateAgreement(otherPublicKey).ToByteArrayUnsigned();

                // take away classical ciphertext
                ciphertext = ciphertext.Skip(publicKeySize).ToArray();
            }
            else if (hybridPrivKey.Classical is RsaKeyParameters)
            {
                // TODO
                throw new NotImplementedException("Rsa hybrid decapsulation not supported");
            }

            if (classicalSharedSecret == null)
            {
                throw new Exception("Classical keytype not supported");
            }

            byte[] postQuantumSharedSecret = null;
            if (hybridPrivKey.PostQuantum is KyberPrivateKeyParameters)
            {
                var extractor = new KyberKemExtractor(hybridPrivKey.PostQuantum as KyberPrivateKeyParameters);
                if (ciphertext.Length != extractor.EncapsulationLength)
                {
                    throw new Exception("Wrong size post-quantum ciphertext");
                }
                postQuantumSharedSecret = new KyberKemExtractor(hybridPrivKey.PostQuantum as KyberPrivateKeyParameters).ExtractSecret(ciphertext);
            }

            if (postQuantumSharedSecret == null)
            {
                throw new Exception("Post-quantum keytype not supported");
            }

            return Arrays.Concatenate(classicalSharedSecret, postQuantumSharedSecret);
        }
    }
}
