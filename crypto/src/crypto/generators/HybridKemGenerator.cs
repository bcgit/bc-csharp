using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.MLKem;
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
            else if (parameters.ClassicalParameters is X25519KeyGenerationParameters)
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(parameters.ClassicalParameters);
                classicalKeypair = generator.GenerateKeyPair();
            }
            else if (parameters.ClassicalParameters is Ed25519KeyGenerationParameters)
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(parameters.ClassicalParameters);
                classicalKeypair = generator.GenerateKeyPair();
            }
            else if (parameters.ClassicalParameters is X448KeyGenerationParameters)
            {
                var generator = new X448KeyPairGenerator();
                generator.Init(parameters.ClassicalParameters);
                classicalKeypair = generator.GenerateKeyPair();
            }
            else if (parameters.ClassicalParameters is Ed448KeyGenerationParameters)
            {
                var generator = new Ed448KeyPairGenerator();
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
            if (parameters.PostQuantumParameters is MLKemKeyGenerationParameters)
            {
                var generator = new MLKemKeyPairGenerator();
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
            if (hybridPubKey.Classical is ECPublicKeyParameters ecPublicKey)
            {
                var generator = new ECKeyPairGenerator("ECDH");
                var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ecPublicKey);
                var domainParameters = new ECDomainParameters(ecPublicKey.Parameters.Curve, ecPublicKey.Parameters.G, ecPublicKey.Parameters.N);
                var parameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
                generator.Init(parameters);
                var ephemeralKeypair = generator.GenerateKeyPair();

                classicalCiphertext = (ephemeralKeypair.Public as ECPublicKeyParameters).Q.GetEncoded();

                var agreement = new ECDHBasicAgreement();
                agreement.Init(ephemeralKeypair.Private);
                classicalSharedSecret = agreement.CalculateAgreement(ecPublicKey).ToByteArrayUnsigned();
            }
            else if (hybridPubKey.Classical is X25519PublicKeyParameters x25519PublicKey)
            {
                var generator = new X25519KeyPairGenerator();
                var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(x25519PublicKey);
                var parameters = new X25519KeyGenerationParameters(new SecureRandom());
                generator.Init(parameters);
                var ephemeralKeypair = generator.GenerateKeyPair();

                classicalCiphertext = (ephemeralKeypair.Public as X25519PublicKeyParameters).GetEncoded();

                var agreement = new X25519Agreement();
                agreement.Init(ephemeralKeypair.Private);
                classicalSharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(x25519PublicKey, classicalSharedSecret, 0);
            }
            else if (hybridPubKey.Classical is X448PublicKeyParameters x448PublicKey)
            {
                var generator = new X448KeyPairGenerator();
                var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(x448PublicKey);
                var parameters = new X448KeyGenerationParameters(new SecureRandom());
                generator.Init(parameters);
                var ephemeralKeypair = generator.GenerateKeyPair();

                classicalCiphertext = (ephemeralKeypair.Public as X448PublicKeyParameters).GetEncoded();

                var agreement = new X448Agreement();
                agreement.Init(ephemeralKeypair.Private);
                classicalSharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(x448PublicKey, classicalSharedSecret, 0);
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
            if (hybridPubKey.PostQuantum is MLKemPublicKeyParameters)
            {
                var encapsulation = new MLKemGenerator(new SecureRandom()).GenerateEncapsulated(hybridPubKey.PostQuantum);
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
            if (hybridPrivKey.Classical is ECPrivateKeyParameters ecPrivateKey)
            {
                // public key is uncompressed ec point
                var publicKeySize = (ecPrivateKey.Parameters.Curve.FieldElementEncodingLength * 2) + 1;

                if (ciphertext.Length <= publicKeySize)
                {
                    throw new Exception("Wrong size classical ciphertext");
                }

                var publicKeyBytes = ciphertext.Take(publicKeySize).ToArray();
                var otherPublicKey = new ECPublicKeyParameters(ecPrivateKey.Parameters.Curve.DecodePoint(publicKeyBytes), ecPrivateKey.Parameters);

                var agreement = new ECDHBasicAgreement();
                agreement.Init(ecPrivateKey);
                classicalSharedSecret = agreement.CalculateAgreement(otherPublicKey).ToByteArrayUnsigned();

                // take away classical ciphertext
                ciphertext = ciphertext.Skip(publicKeySize).ToArray();
            }
            else if (hybridPrivKey.Classical is X25519PrivateKeyParameters x25519PrivateKey)
            {
                var publicKeySize = X25519PrivateKeyParameters.KeySize;

                if (ciphertext.Length <= publicKeySize)
                {
                    throw new Exception("Wrong size classical ciphertext");
                }

                var publicKeyBytes = ciphertext.Take(publicKeySize).ToArray();
                var otherPublicKey = new X25519PublicKeyParameters(publicKeyBytes);

                var agreement = new X25519Agreement();
                agreement.Init(x25519PrivateKey);
                classicalSharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(otherPublicKey, classicalSharedSecret, 0);

                ciphertext = ciphertext.Skip(publicKeySize).ToArray();
            }
            else if (hybridPrivKey.Classical is X448PrivateKeyParameters x448PrivateKey)
            {
                var publicKeySize = X448PrivateKeyParameters.KeySize;

                if (ciphertext.Length <= publicKeySize)
                {
                    throw new Exception("Wrong size classical ciphertext");
                }

                var publicKeyBytes = ciphertext.Take(publicKeySize).ToArray();
                var otherPublicKey = new X448PublicKeyParameters(publicKeyBytes);

                var agreement = new X448Agreement();
                agreement.Init(x448PrivateKey);
                classicalSharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(otherPublicKey, classicalSharedSecret, 0);

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
            if (hybridPrivKey.PostQuantum is MLKemPrivateKeyParameters postQuantum)
            {
                var extractor = new MLKemExtractor(postQuantum);
                if (ciphertext.Length != extractor.EncapsulationLength)
                {
                    throw new Exception("Wrong size post-quantum ciphertext");
                }
                postQuantumSharedSecret = extractor.ExtractSecret(ciphertext);
            }

            if (postQuantumSharedSecret == null)
            {
                throw new Exception("Post-quantum keytype not supported");
            }

            return Arrays.Concatenate(classicalSharedSecret, postQuantumSharedSecret);
        }
    }
}
