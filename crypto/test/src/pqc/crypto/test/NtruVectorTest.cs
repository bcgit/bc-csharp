using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class NtruVectorTest
    {
        private static readonly Dictionary<string, NtruParameters> Parameters = new Dictionary<string, NtruParameters>()
        {
            { "ntruhps2048509/PQCkemKAT_935.rsp", NtruParameters.NtruHps2048509 },
            { "ntruhps2048677/PQCkemKAT_1234.rsp", NtruParameters.NtruHps2048677 },
            { "ntruhps4096821/PQCkemKAT_1590.rsp", NtruParameters.NtruHps4096821 },
            { "ntruhps40961229/PQCkemKAT_2366.rsp", NtruParameters.NtruHps40961229 },
            { "ntruhrss701/PQCkemKAT_1450.rsp", NtruParameters.NtruHrss701 },
            { "ntruhrss1373/PQCkemKAT_2983.rsp", NtruParameters.NtruHrss1373 },
        };
        
        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(256, NtruParameters.NtruHps4096821.DefaultKeySize);
            Assert.AreEqual(256, NtruParameters.NtruHps2048509.DefaultKeySize);
            Assert.AreEqual(256, NtruParameters.NtruHps2048677.DefaultKeySize);
            Assert.AreEqual(256, NtruParameters.NtruHps40961229.DefaultKeySize);
            Assert.AreEqual(256, NtruParameters.NtruHrss701.DefaultKeySize);
        }

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] ct = Hex.Decode(buf["ct"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] ss = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruParameters ntruParameters = Parameters[name];

            // Test keygen
            NtruKeyGenerationParameters keygenParameters =
                new NtruKeyGenerationParameters(random, ntruParameters);

            NtruKeyPairGenerator keygen = new NtruKeyPairGenerator();
            keygen.Init(keygenParameters);
            AsymmetricCipherKeyPair keyPair = keygen.GenerateKeyPair();

            NtruPublicKeyParameters pubParams = (NtruPublicKeyParameters)keyPair.Public;
            NtruPrivateKeyParameters privParams = (NtruPrivateKeyParameters)keyPair.Private;

            Assert.True(Arrays.AreEqual(pk, pubParams.PublicKey), $"{name} {count} : public key");
            Assert.True(Arrays.AreEqual(sk, privParams.PrivateKey), $"{name} {count} : private key");

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

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.FindTestResource("pqc/crypto/ntru", name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf("=");
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0)
                    {
                        if (!sampler.SkipTest(buf["count"]))
                        {
                            RunTestVector(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVector(name, buf);
                    }
                    buf.Clear();
                }
            }
        }

        //[Test]
        //public void TestPrivInfoGeneration()
        //{
        //    SecureRandom random = new SecureRandom();
        //    PqcOtherInfoGenerator.PartyU partyU = new PqcOtherInfoGenerator.PartyU(NtruParameters.NtruHrss701, new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), Hex.Decode("beef"), Hex.Decode("cafe"), random);
        //    byte[] partA = partyU.GetSuppPrivInfoPartA();
        //    PqcOtherInfoGenerator.PartyV partyV = new PqcOtherInfoGenerator.PartyV(NtruParameters.NtruHrss701, new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), Hex.Decode("beef"), Hex.Decode("cafe"), random);
        //    byte[] partB = partyV.GetSuppPrivInfoPartB(partA);
        //    DerOtherInfo otherInfoU = partyU.Generate(partB);
        //    DerOtherInfo otherInfoV = partyV.Generate();
        //    Assert.True(Arrays.AreEqual(otherInfoU.GetEncoded(), otherInfoV.GetEncoded()));
        //}
    }
}
