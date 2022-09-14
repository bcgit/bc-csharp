using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

using PrivateKeyFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.PrivateKeyFactory;
using PrivateKeyInfoFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.PrivateKeyInfoFactory;
using PublicKeyFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.PublicKeyFactory;
using SubjectPublicKeyInfoFactory = Org.BouncyCastle.Pqc.Crypto.Utilities.SubjectPublicKeyInfoFactory;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class CmceVectorTest
    {
        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(128, CmceParameters.mceliece348864r3.DefaultKeySize);
            Assert.AreEqual(128, CmceParameters.mceliece348864fr3.DefaultKeySize);
            Assert.AreEqual(192, CmceParameters.mceliece460896r3.DefaultKeySize);
            Assert.AreEqual(192, CmceParameters.mceliece460896fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6688128r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6688128fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6960119r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece6960119fr3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece8192128r3.DefaultKeySize);
            Assert.AreEqual(256, CmceParameters.mceliece8192128fr3.DefaultKeySize);
        }
        
        [Test]
        public void TestVectors()
        {

            //todo change to project property
            // bool full = System.GetProperty("test.full", "false").equals("true");
            bool full = false;
            
            string[] files;
            if (full)
            {
                files = new []{
                    "3488-64-cmce.txt",
                    "3488-64-f-cmce.txt",
                    "4608-96-cmce.txt",
                    "4608-96-f-cmce.txt",
                    "6688-128-cmce.txt",
                    "6688-128-f-cmce.txt",
                    "6960-119-cmce.txt",
                    "6960-119-f-cmce.txt",
                    "8192-128-cmce.txt",
                    "8192-128-f-cmce.txt"
                };
            }
            else
            {
                files = new []{
                    "3488-64-cmce.txt",
                    "3488-64-f-cmce.txt",
                };
            }

            CmceParameters[] parameters = {
                CmceParameters.mceliece348864r3,
                CmceParameters.mceliece348864fr3,
                CmceParameters.mceliece460896r3,
                CmceParameters.mceliece460896fr3,
                CmceParameters.mceliece6688128r3,
                CmceParameters.mceliece6688128fr3,
                CmceParameters.mceliece6960119r3,
                CmceParameters.mceliece6960119fr3,
                CmceParameters.mceliece8192128r3,
                CmceParameters.mceliece8192128fr3
            };

            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                string name = files[fileIndex];
                Console.Write($"testing: {name}");
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.cmce." + name));
                // BufferedReader bin = new BufferedReader(new InputStreamReader(src));

                string line = null;
                Dictionary<string, string> buf = new Dictionary<string, string>();
                // Random rnd = new Random(System.currentTimeMillis());
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }
                    if (line.Length == 0)
                    {
                        if (buf.Count > 0)
                        {
                            string count = buf["count"];
                            if (!"0".Equals(count))
                            {
                                // randomly skip tests after zero.
                                // if (rnd.nextBoolean())
                                // {
                                //     continue;
                                // }
                            }
                            Console.Write($"test case: {count}\n");
                            byte[] seed = Hex.Decode(buf["seed"]); // seed for Cmce secure random
                            byte[] pk = Hex.Decode(buf["pk"]);     // public key
                            byte[] sk = Hex.Decode(buf["sk"]);     // private key
                            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]);     // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            CmceParameters Cmceparameters = parameters[fileIndex];

                            CmceKeyPairGenerator kpGen = new CmceKeyPairGenerator();
                            CmceKeyGenerationParameters genParam = new CmceKeyGenerationParameters(random, Cmceparameters);
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParam);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            CmcePublicKeyParameters pubParams = (CmcePublicKeyParameters)PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((CmcePublicKeyParameters)kp.Public));
                            CmcePrivateKeyParameters privParams = (CmcePrivateKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo((CmcePrivateKeyParameters)kp.Private));

                            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), name + " " + count + ": public key");
                            Assert.True(Arrays.AreEqual(sk, privParams.PrivateKey), name + " " + count + ": secret key");

                            // KEM Enc
                            CmceKemGenerator CmceEncCipher = new CmceKemGenerator(random);
                            ISecretWithEncapsulation secWenc = CmceEncCipher.GenerateEncapsulated(pubParams, 256);
                            byte[] generated_cipher_text = secWenc.GetEncapsulation();
                            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

                            // KEM Dec
                            CmceKemExtractor CmceDecCipher = new CmceKemExtractor(privParams);

                            byte[] dec_key = CmceDecCipher.ExtractSecret(generated_cipher_text, 256);

                            Assert.True(Arrays.AreEqual(dec_key, ss), name + " " + count + ": kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
                        }
                        buf.Clear();

                        continue;
                    }

                    int a = line.IndexOf('=');
                    if (a > -1)
                    {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }


                }
                Console.Write("testing successful!");
            }

        }
    }
}