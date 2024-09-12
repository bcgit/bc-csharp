using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.crypto.generators;
using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.src.crypto.test
{
    [TestFixture]
    public class PQCHybridTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static List<string> postQuantumKems = new List<string>()
        {
            "mlkem512",
            "mlkem768",
            "mlkem1024",
        };

        private static List<string> classicalEcdh = new List<string>()
        {
            "p256",
            "p384",
            "p521",
            "x25519",
            "x448",
        };

        private static List<string> postQuantumSignatures = new List<string>()
        {
            "mldsa44",
            "mldsa65",
            "mldsa87",
            "slhdsasha2128f",
            "slhdsasha2192f",
            "slhdsasha2256f",
            "slhdsasha2128s",
            "slhdsasha2192s",
            "slhdsasha2256s",
            "slhdsashake128f",
            "slhdsashake192f",
            "slhdsashake256f",
            "slhdsashake128s",
            "slhdsashake192s",
            "slhdsashake256s",
        };

        private static List<string> classicalSignatures = new List<string>()
        {
            "p256",
            "p384",
            "p521",
            "x25519",
            "x448",
        };

        [Test]
        public void TestKems()
        {
            foreach (var postQuantum in postQuantumKems)
            {
                foreach (var classical in classicalEcdh)
                {
                    var hybridName = $"{classical}_{postQuantum}";

                    // generate keypair
                    var keypair = GenerateKeypair(hybridName, true);

                    if (keypair == null) continue;

                    // encode/decode

                    var pubKey = PublicTryEnDecode(keypair.Public);

                    var privKey = PrivateTryEnDecode(keypair.Private);

                    // encapsulate
                    var encapsulation = HybridKemGenerator.Encapsulate(pubKey);

                    // decapsulate
                    var secret = HybridKemGenerator.Decapsulate(privKey, encapsulation.GetEncapsulation());
                    Assert.AreEqual(encapsulation.GetSecret(), secret);

                    Console.WriteLine($"success: {hybridName}");
                }
            }
        }

        [Test]
        public void TestSignatures()
        {
            foreach (var postQuantum in postQuantumSignatures)
            {
                foreach (var classical in classicalSignatures)
                {
                    var hybridName = $"{classical}_{postQuantum}";

                    // generate keypair
                    var keypair = GenerateKeypair(hybridName, false);

                    if (keypair == null) continue;

                    // encode/decode

                    var pubKey = PublicTryEnDecode(keypair.Public);

                    var privKey = PrivateTryEnDecode(keypair.Private);

                    // random message
                    byte[] message = new byte[32];
                    Random.NextBytes(message);

                    // sign
                    var signature = HybridSignatureGenerator.GenerateSignature(privKey, message);

                    // verify
                    Assert.IsTrue(HybridSignatureGenerator.VerifySignature(pubKey, message, signature));

                    Console.WriteLine($"success: {hybridName}");
                }
            }
        }

        [Test]
        public void TestInterop()
        {
            var otherLibraries = new List<string>()
            {
                "oqsprovider",
            };

            foreach (var lib in otherLibraries)
            {
                Console.WriteLine($"testing interop with: {lib}");
                TestKemInteropWith(lib);
            }
        }

        private static AsymmetricCipherKeyPair GenerateKeypair(string hybridName, bool isKem)
        {
            HybridKeyGenerationParameters hybridParameters;
            try
            {
                hybridParameters = new HybridKeyGenerationParameters(Random, hybridName);
            }
            catch (ArgumentException ex) when (ex.Message.Equals("Unsupported hybrid combination"))
            {
                return null;
            }
            if (isKem)
            {
                var generator = new HybridKemGenerator();
                generator.Init(hybridParameters);
                return generator.GenerateKeyPair();
            }
            else
            {
                var generator = new HybridSignatureGenerator();
                generator.Init(hybridParameters);
                return generator.GenerateKeyPair();
            }
        }

        private static AsymmetricKeyParameter PublicTryEnDecode(AsymmetricKeyParameter pubKey)
        {
            // encode
            var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            var pubKeyBytes = pubKeyInfo.GetEncoded();

            // decode
            var pubKey1 = PublicKeyFactory.CreateKey(pubKeyInfo);
            var pubKey2 = PublicKeyFactory.CreateKey(pubKeyBytes);

            return pubKey2;
        }

        private static AsymmetricKeyParameter PrivateTryEnDecode(AsymmetricKeyParameter privKey)
        {
            // encode
            var privKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey);
            var privKeyInfoBytes = privKeyInfo.GetEncoded();

            // decode
            var privKey1 = PrivateKeyFactory.CreateKey(privKeyInfo);
            var privKey2 = PrivateKeyFactory.CreateKey(privKeyInfoBytes);

            return privKey2;
        }

        private static void TestKemInteropWith(string libraryName)
        {
            foreach (var postQuantum in postQuantumKems)
            {
                foreach (var classical in classicalEcdh)
                {
                    var hybridName = $"{classical}_{postQuantum}";

                    AsymmetricKeyParameter privKey = null;
                    AsymmetricKeyParameter pubKey = null;
                    byte[] ciphertext = null;
                    byte[] sharedSecret = null;

                    var directoryName = "hybrid." + libraryName + ".kem." + hybridName;

                    if (!SimpleTest.TestDataDirectoryExists(directoryName))
                        continue;

                    using (var sr = new StringReader(System.Text.Encoding.ASCII.GetString(SimpleTest.GetTestData(directoryName + ".privkey.pem"))))
                    {
                        var reader = new PemReader(sr);
                        privKey = (HybridKeyParameters)reader.ReadObject();
                    }

                    using (var sr = new StringReader(System.Text.Encoding.ASCII.GetString(SimpleTest.GetTestData(directoryName + ".pubkey.pem"))))
                    {
                        var reader = new PemReader(sr);
                        pubKey = (HybridKeyParameters)reader.ReadObject();
                    }

                    using (var sr = new StringReader(System.Text.Encoding.ASCII.GetString(SimpleTest.GetTestData(directoryName + ".ciphertext.base64.txt").Skip(3).ToArray())))
                    {
                        ciphertext = Convert.FromBase64String(sr.ReadToEnd());
                    }

                    using (var sr = new StringReader(System.Text.Encoding.ASCII.GetString(SimpleTest.GetTestData(directoryName + ".shared_secret.base64.txt").Skip(3).ToArray())))
                    {
                        sharedSecret = Convert.FromBase64String(sr.ReadToEnd());
                    }

                    var pubKey2 = PublicTryEnDecode(pubKey);

                    var privKey2 = PrivateTryEnDecode(privKey);

                    // decapsulate serialized ciphertext
                    var sharedSecret2 = HybridKemGenerator.Decapsulate(privKey, ciphertext);
                    Assert.AreEqual(sharedSecret, sharedSecret2);

                    var sharedSecret3 = HybridKemGenerator.Decapsulate(privKey2, ciphertext);
                    Assert.AreEqual(sharedSecret, sharedSecret3);

                    // encapsulate
                    var newEncapsulation = HybridKemGenerator.Encapsulate(pubKey);

                    // decapsulate
                    var newSharedSecret = HybridKemGenerator.Decapsulate(privKey, newEncapsulation.GetEncapsulation());
                    Assert.AreEqual(newEncapsulation.GetSecret(), newSharedSecret);

                    Console.WriteLine($"success: {hybridName}");
                }
            }
        }
    }
}
