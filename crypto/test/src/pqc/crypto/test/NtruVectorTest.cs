using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

using NtruKeyPairGenerator = Org.BouncyCastle.Pqc.Crypto.Ntru.NtruKeyPairGenerator;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class NtruVectorTest
    {
        [Test]
        public void TestVectors()
        {
            string[] files =
            {
                "PQCkemKAT_935.rsp", // NtruHps2048509
                "PQCkemKAT_1234.rsp", // NtruHps2048677
                "PQCkemKAT_1590.rsp", // NtruHps4096821
                "PQCkemKAT_1450.rsp" // NtruHrss701
            };

            NtruParameters[] parameters =
            {
                NtruParameters.NtruHps2048509,
                NtruParameters.NtruHps2048677,
                NtruParameters.NtruHps4096821,
                NtruParameters.NtruHrss701
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                string name = files[fileIndex];
                Console.Write("Testing " + name + "...");
                Console.WriteLine("pqc.ntru." + name);
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.ntru." + name));
                String line;
                Dictionary<String, String> buf = new Dictionary<string, string>();

                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                    {
                        continue;
                    }

                    if (line.Length == 0)
                    {
                        if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                        {
                            String count = buf["count"];

                            if (!"0".Equals(count))
                            {
                                // Console.WriteLine("Zero");
                            }

                            byte[] seed = Hex.Decode(buf["seed"]);
                            byte[] pk = Hex.Decode(buf["pk"]);
                            byte[] ct = Hex.Decode(buf["ct"]);
                            byte[] sk = Hex.Decode(buf["sk"]);
                            byte[] ss = Hex.Decode(buf["ss"]);

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            NtruParameters ntruParameters = parameters[fileIndex];
                            
                            // Test keygen
                            NtruKeyGenerationParameters keygenParameters =
                                new NtruKeyGenerationParameters(random, ntruParameters);
                            
                            NtruKeyPairGenerator keygen = new NtruKeyPairGenerator();
                            keygen.Init(keygenParameters);
                            AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();
                            
                            NtruPublicKeyParameters pubParams = (NtruPublicKeyParameters)keyPair.Public;
                            NtruPrivateKeyParameters privParams = (NtruPrivateKeyParameters)keyPair.Private;
                            
                            Assert.True(Arrays.AreEqual(pk,pubParams.PublicKey), $"{name} {count} : public key");
                            Assert.True(Arrays.AreEqual(sk,privParams.PrivateKey), $"{name} {count} : private key");
                            
                            // Test encapsulate
                            NtruKemGenerator encapsulator = new NtruKemGenerator(random);
                            ISecretWithEncapsulation encapsulation = encapsulator.GenerateEncapsulated(new NtruPublicKeyParameters(ntruParameters, pk));
                            byte[] generatedSecret = encapsulation.GetSecret();
                            byte[] generatedCiphertext = encapsulation.GetEncapsulation();

                            Assert.AreEqual(generatedSecret.Length, ntruParameters.DefaultKeySize / 8);
                            Assert.True(Arrays.AreEqual(ss, 0, generatedSecret.Length, generatedSecret, 0, generatedSecret.Length), $"{name} {count} : shared secret");
                            Assert.True(Arrays.AreEqual(ct, generatedCiphertext), $"{name} {count} : ciphertext");

                            // Test decapsulate
                            NtruKemExtractor decapsulator = new NtruKemExtractor(new NtruPrivateKeyParameters(ntruParameters, sk));
                            byte[] extractedSecret = decapsulator.ExtractSecret(ct);
                            Assert.AreEqual(generatedSecret.Length, extractedSecret.Length);
                            Assert.True(Arrays.AreEqual(ss, 0, extractedSecret.Length, extractedSecret, 0, extractedSecret.Length), $"{name} {count} : extract secret");

                        }
                        buf.Clear();
                        continue;
                    }
                    int a = line.IndexOf("=");
                    if (a > -1)
                    {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
                Console.WriteLine("OK");
            }
        }
    }
}
