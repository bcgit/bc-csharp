using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Pqc.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security;
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
            if (!(privKey is HybridKeyParameters))
            {
                throw new ArgumentException("Provided key parameter is not hybrid");
            }
            if (!privKey.IsPrivate)
            {
                throw new ArgumentException("Provided key is not a private key");
            }

            var hybridPrivKey = privKey as HybridKeyParameters;

            byte[] classicalSignature = null;
            if (hybridPrivKey.Classical is ECPrivateKeyParameters ecPrivKey)
            {
                var signer = new ECDsaSigner();
                signer.Init(true, ecPrivKey);
                var signature = signer.GenerateSignature(message);
                classicalSignature = Arrays.Concatenate(signature[0].ToByteArrayUnsigned(), signature[1].ToByteArrayUnsigned());
            }
            else if (hybridPrivKey.Classical is Ed25519PrivateKeyParameters ed25519PrivKey)
            {
                var signer = new Ed25519Signer();
                signer.Init(true, ed25519PrivKey);
                signer.BlockUpdate(message, 0, message.Length);
                classicalSignature = signer.GenerateSignature();
            }
            else if (hybridPrivKey.Classical is Ed448PrivateKeyParameters ed448PrivKey)
            {
                var signer = new Ed448Signer(message);
                signer.Init(true, ed448PrivKey);
                signer.BlockUpdate(message, 0, message.Length);
                classicalSignature = signer.GenerateSignature();
            }
            else if (hybridPrivKey.Classical is RsaKeyParameters)
            {
                // TODO
                throw new NotImplementedException("Rsa hybrid signature generation not supported");
            }

            if (classicalSignature == null)
            {
                throw new Exception("Classical keytype not supported");
            }

            byte[] postQuantumSignature = null;
            if (hybridPrivKey.PostQuantum is DilithiumKeyParameters)
            {
                var signer = new DilithiumSigner();
                signer.Init(true, hybridPrivKey.PostQuantum);
                postQuantumSignature = signer.GenerateSignature(message);
            }
            else if (hybridPrivKey.PostQuantum is SphincsPlusKeyParameters)
            {
                var signer = new SphincsPlusSigner();
                signer.Init(true, hybridPrivKey.PostQuantum);
                postQuantumSignature = signer.GenerateSignature(message);
            }

            if (postQuantumSignature == null)
            {
                throw new Exception("Post-quantum keytype not supported");
            }

            return Arrays.Concatenate(classicalSignature, postQuantumSignature);
        }

        public static bool VerifySignature(AsymmetricKeyParameter pubKey, byte[] message, byte[] signature)
        {
            if (!(pubKey is HybridKeyParameters))
            {
                throw new ArgumentException("Provided key parameter is not hybrid");
            }

            var hybridPubKey = pubKey as HybridKeyParameters;

            bool classicalVerified = false;
            if (hybridPubKey.Classical is ECPublicKeyParameters ecPublicKey)
            {
                var domainParameters = ecPublicKey.Parameters;
                var classicalSignatureLength = (domainParameters.N.BitLength / 8) * 2;

                if (signature.Length <= classicalSignatureLength)
                {
                    throw new Exception("Wrong size signature");
                }

                var classicalSignatureBytes = signature.Take(classicalSignatureLength).ToArray();
                var r = new Math.BigInteger(classicalSignatureBytes.Take(classicalSignatureLength / 2).ToArray());
                var s = new Math.BigInteger(classicalSignatureBytes.Skip(classicalSignatureLength / 2).ToArray());

                var verifier = new ECDsaSigner();
                verifier.Init(false, hybridPubKey.Classical);
                if(!verifier.VerifySignature(message, r, s))
                {
                    throw new VerificationException("Signature verification failed");
                }

                // take away classical signature
                signature = signature.Skip(classicalSignatureLength).ToArray();

                classicalVerified = true;
            }
            else if (hybridPubKey.Classical is Ed25519PublicKeyParameters ed25519PublicKey)
            {
                var classicalSignatureLength = Ed25519.SignatureSize;

                if (signature.Length <= classicalSignatureLength)
                {
                    throw new Exception("Wrong size signature");
                }

                var classicalSignatureBytes = signature.Take(classicalSignatureLength).ToArray();

                var verifier = new Ed25519Signer();
                verifier.Init(true, ed25519PublicKey);
                verifier.BlockUpdate(message, 0, message.Length);
                if(!verifier.VerifySignature(signature))
                {
                    throw new VerificationException("Signature verification failed");
                }

                // take away classical signature
                signature = signature.Skip(classicalSignatureLength).ToArray();

                classicalVerified = true;
            }
            else if (hybridPubKey.Classical is Ed448PublicKeyParameters ed448PublicKey)
            {
                var classicalSignatureLength = Ed448.SignatureSize;

                if (signature.Length <= classicalSignatureLength)
                {
                    throw new Exception("Wrong size signature");
                }

                var classicalSignatureBytes = signature.Take(classicalSignatureLength).ToArray();

                var verifier = new Ed448Signer(message);
                verifier.Init(true, ed448PublicKey);
                if(!verifier.VerifySignature(signature))
                {
                    throw new VerificationException("Signature verification failed");
                }

                // take away classical signature
                signature = signature.Skip(classicalSignatureLength).ToArray();

                classicalVerified = true;
            }
            else if (hybridPubKey.Classical is RsaKeyParameters)
            {
                // TODO
                throw new NotImplementedException("Rsa hybrid signature verification not supported");
            }

            if (!classicalVerified)
            {
                throw new Exception("Classical keytype not supported");
            }

            bool postQuantumVerified = false;
            if (hybridPubKey.PostQuantum is DilithiumPublicKeyParameters)
            {
                var verifier = new DilithiumSigner();
                verifier.Init(false, hybridPubKey.PostQuantum);
                if (!verifier.VerifySignature(message, signature))
                {
                    throw new VerificationException("Signature verification failed");
                }

                postQuantumVerified = true;
            }
            else if (hybridPubKey.PostQuantum is SphincsPlusPublicKeyParameters)
            {
                var verifier = new SphincsPlusSigner();
                verifier.Init(false, hybridPubKey.PostQuantum);
                if (!verifier.VerifySignature(message, signature))
                {
                    throw new VerificationException("Signature verification failed");
                }

                postQuantumVerified = true;
            }

            if (!postQuantumVerified)
            {
                throw new Exception("Post-quantum keytype not supported");
            }

            return true;
        }
    }
}
