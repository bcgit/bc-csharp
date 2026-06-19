using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class DHTest
    {
        private static readonly BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        private static readonly BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        private static readonly BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
        private static readonly BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

        private static readonly BigInteger g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
        private static readonly BigInteger p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

        private void ImplTestDH(int size, BigInteger g, BigInteger p)
        {
            DHKeyPairGenerator kpGen = GetDHKeyPairGenerator(g, p);

            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu1 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv1 = (DHPrivateKeyParameters)pair.Private;
            //
            // generate second pair
            //
            pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu2 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv2 = (DHPrivateKeyParameters)pair.Private;

            //
            // two way
            //
            DHAgreement e1 = new DHAgreement();
            DHAgreement e2 = new DHAgreement();

            e1.Init(pv1);
            e2.Init(pv2);

            BigInteger m1 = e1.CalculateMessage();
            BigInteger m2 = e2.CalculateMessage();

            BigInteger k1 = e1.CalculateAgreement(pu2, m2);
            BigInteger k2 = e2.CalculateAgreement(pu1, m1);

            Assert.AreEqual(k1, k2, size + " bit 2-way test failed");
        }

        private void ImplTestDHBasic(int size, int privateValueSize, BigInteger g, BigInteger p)
        {
            DHBasicKeyPairGenerator kpGen = GetDHBasicKeyPairGenerator(g, p, privateValueSize);

            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu1 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv1 = (DHPrivateKeyParameters)pair.Private;

            CheckKeySize(privateValueSize, pv1);
            //
            // generate second pair
            //
            pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu2 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv2 = (DHPrivateKeyParameters)pair.Private;

            CheckKeySize(privateValueSize, pv2);
            //
            // two way
            //
            DHBasicAgreement e1 = new DHBasicAgreement();
            DHBasicAgreement e2 = new DHBasicAgreement();

            e1.Init(pv1);
            e2.Init(pv2);

            BigInteger k1 = e1.CalculateAgreement(pu2);
            BigInteger k2 = e2.CalculateAgreement(pu1);

            Assert.AreEqual(k1, k2, "basic " + size + " bit 2-way test failed");
        }

        private void CheckKeySize(int privateValueSize, DHPrivateKeyParameters priv)
        {
            if (privateValueSize != 0)
            {
                Assert.AreEqual(privateValueSize, priv.X.BitLength,
                    "limited key check failed for key size " + privateValueSize);
            }
        }

        private void ImplTestGPWithRandom(DHKeyPairGenerator kpGen)
        {
            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu1 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv1 = (DHPrivateKeyParameters)pair.Private;
            //
            // generate second pair
            //
            pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu2 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv2 = (DHPrivateKeyParameters)pair.Private;

            //
            // two way
            //
            DHAgreement e1 = new DHAgreement();
            DHAgreement e2 = new DHAgreement();

            e1.Init(new ParametersWithRandom(pv1, new SecureRandom()));
            e2.Init(new ParametersWithRandom(pv2, new SecureRandom()));

            BigInteger m1 = e1.CalculateMessage();
            BigInteger m2 = e2.CalculateMessage();

            BigInteger k1 = e1.CalculateAgreement(pu2, m2);
            BigInteger k2 = e2.CalculateAgreement(pu1, m1);

            Assert.AreEqual(k1, k2, "basic with random 2-way test failed");
        }

        private void ImplTestSimpleWithRandom(DHBasicKeyPairGenerator kpGen)
        {
            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu1 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv1 = (DHPrivateKeyParameters)pair.Private;
            //
            // generate second pair
            //
            pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu2 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv2 = (DHPrivateKeyParameters)pair.Private;

            //
            // two way
            //
            DHBasicAgreement e1 = new DHBasicAgreement();
            DHBasicAgreement e2 = new DHBasicAgreement();

            e1.Init(new ParametersWithRandom(pv1, new SecureRandom()));
            e2.Init(new ParametersWithRandom(pv2, new SecureRandom()));

            BigInteger k1 = e1.CalculateAgreement(pu2);
            BigInteger k2 = e2.CalculateAgreement(pu1);

            Assert.AreEqual(k1, k2, "basic with random 2-way test failed");
        }

        // NOTE: This test can take quiet a while
        private void ImplTestGeneration(int size)
        {
            DHParametersGenerator pGen = new DHParametersGenerator();
            pGen.Init(size, 10, new SecureRandom());

            DHParameters dhParams = pGen.GenerateParameters();
            Assert.AreEqual(0, dhParams.L, "DHParametersGenerator failed to set L to 0 in generated DHParameters");

            DHBasicKeyPairGenerator kpGen = new DHBasicKeyPairGenerator();
            kpGen.Init(new DHKeyGenerationParameters(new SecureRandom(), dhParams));

            //
            // generate first pair
            //
            AsymmetricCipherKeyPair pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu1 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv1 = (DHPrivateKeyParameters)pair.Private;

            //
            // generate second pair
            //
            kpGen.Init(new DHKeyGenerationParameters(new SecureRandom(), pu1.Parameters));

            pair = kpGen.GenerateKeyPair();

            DHPublicKeyParameters pu2 = (DHPublicKeyParameters)pair.Public;
            DHPrivateKeyParameters pv2 = (DHPrivateKeyParameters)pair.Private;

            //
            // two way
            //
            DHBasicAgreement e1 = new DHBasicAgreement();
            DHBasicAgreement e2 = new DHBasicAgreement();

            e1.Init(new ParametersWithRandom(pv1, new SecureRandom()));
            e2.Init(new ParametersWithRandom(pv2, new SecureRandom()));

            BigInteger k1 = e1.CalculateAgreement(pu2);
            BigInteger k2 = e2.CalculateAgreement(pu1);

            Assert.AreEqual(k1, k2, "basic with " + size + " bit 2-way test failed");
        }

        [Test]
        public void Basic()
        {
            ImplTestDHBasic(512, 0, g512, p512);
            ImplTestDHBasic(768, 0, g768, p768);
            ImplTestDHBasic(1024, 0, g1024, p1024);

            ImplTestDHBasic(512, 64, g512, p512);
            ImplTestDHBasic(768, 128, g768, p768);
            ImplTestDHBasic(1024, 256, g1024, p1024);

            ImplTestDH(512, g512, p512);
            ImplTestDH(768, g768, p768);
            ImplTestDH(1024, g1024, p1024);

            //
            // generation test.
            //
            ImplTestGeneration(256);

            //
            // with random test
            //
            DHBasicKeyPairGenerator kpBasicGen = GetDHBasicKeyPairGenerator(g512, p512, 0);

            ImplTestSimpleWithRandom(kpBasicGen);

            DHKeyPairGenerator kpGen = GetDHKeyPairGenerator(g512, p512);

            ImplTestGPWithRandom(kpGen);

            //
            // parameter tests
            //
            DHAgreement dh = new DHAgreement();
            AsymmetricCipherKeyPair dhPair = kpGen.GenerateKeyPair();

            try
            {
                dh.Init(dhPair.Public);
                Assert.Fail("DHAgreement key check failed");
            }
            catch (ArgumentException)
            {
                // ignore
            }

            DHKeyPairGenerator kpGen768 = GetDHKeyPairGenerator(g768, p768);

            try
            {
                dh.Init(dhPair.Private);

                dh.CalculateAgreement((DHPublicKeyParameters)kpGen768.GenerateKeyPair().Public, BigInteger.ValueOf(100));

                Assert.Fail("DHAgreement agreement check failed");
            }
            catch (ArgumentException)
            {
                // ignore
            }

            DHBasicAgreement dhBasic = new DHBasicAgreement();
            AsymmetricCipherKeyPair dhBasicPair = kpBasicGen.GenerateKeyPair();

            try
            {
                dhBasic.Init(dhBasicPair.Public);
                Assert.Fail("DHBasicAgreement key check failed");
            }
            catch (ArgumentException)
            {
                // expected
            }

            DHBasicKeyPairGenerator kpBasicGen768 = GetDHBasicKeyPairGenerator(g768, p768, 0);

            try
            {
                dhBasic.Init(dhPair.Private);

                dhBasic.CalculateAgreement((DHPublicKeyParameters)kpBasicGen768.GenerateKeyPair().Public);

                Assert.Fail("DHBasicAgreement agreement check failed");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        [Test]
        public void Bounds()
        {
            SecureRandom random = new SecureRandom();

            BigInteger p1 = new BigInteger("00C8028E9151C6B51BCDB35C1F6B2527986A72D8546AE7A4BF41DC4289FF9837EE01592D36C324A0F066149B8B940C86C87D194206A39038AE3396F8E12435BB74449B70222D117B8A2BB77CB0D67A5D664DDE7B75E0FEC13CE0CAF258DAF3ADA0773F6FF0F2051D1859929AAA53B07809E496B582A89C3D7DA8B6E38305626621", 16);
            BigInteger g1 = new BigInteger("1F869713181464577FE4026B47102FA0D7675503A4FCDA810881FAEC3524E6DBAEA9B96561EF7F8BEA76466DF11C2F3EB1A90CC5851735BF860606481257EECE6418C0204E61004E85D7131CE54BCBC7AD67E53C79DCB715E7C8D083DCD85D728283EC8F96839B4C9FA7C0727C472BEB94E4613CAFA8D580119C0AF4BF8AF252", 16);
            int l1 = 1023;

            DHKeyGenerationParameters params1 = new DHKeyGenerationParameters(random, new DHParameters(p1, g1, null, l1));
            DHBasicKeyPairGenerator kpGen = new DHBasicKeyPairGenerator();
            kpGen.Init(params1);

            BigInteger p2 = new BigInteger("00B333C98720220CC3946F494E25231B3E19F9AD5F6B19F4E7ABF80D8826C491C3224D4F7415A14A7C11D1BE584405FED12C3554F103E56A72D986CA5E325BB9DE07AC37D1EAE5E5AC724D32EF638F0E4462D4C1FC7A45B9FD3A5DF5EC36A1FA4DAA3FBB66AA42B1B71DF416AB547E987513426C7BB8634F5F4D37705514FDC1E1", 16);
            BigInteger g2 = new BigInteger("2592F5A99FE46313650CCE66C94C15DBED9F4A45BD05C329986CF5D3E12139F0405A47C6385FEA27BFFEDC4CBABC5BB151F3BEE7CC3D51567F1E2B12A975AA9F48A70BDAAE7F5B87E70ADCF902490A3CBEFEDA41EBA8E12E02B56120B5FDEFBED07F5EAD3AE020DF3C8233216F8F0D35E13A7AE4DA5CBCC0D91EADBF20C281C6", 16);
            int l2 = 1024;

            try
            {
                new DHKeyGenerationParameters(random, new DHParameters(p2, g2, null, l2));
                Assert.Fail("oversized DH 'l' value accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        [Test]
        public void PgenCounterBound()
        {
            // X9 dhpublicnumber domain parameters with a ValidationParams pgenCounter that does not
            // fit in a signed 32-bit int. PublicKeyFactory must reject it rather than silently
            // truncating the counter (which previously produced a corrupt DHValidationParameters).
            BigInteger P = new BigInteger("eedb3431b31d30851ddcd4dce57e1b8fc3b83cc7913bc049281d713d9f8fa91bfd0fde2e1ec5eb45a0d6483cfa6b5055ffa88622a1aa83b9f9c1df561e88b702866f17af2defea0b04cf3fbdd817140ad49c415909fc2bb2c5d160b77273e958a181bf73cf72118e1c8670d53d0e459d14d61ecb5b7c7f63a9cb019cd66aecb3a01d0402f1c18218f142653f4bc922e5baa35964b7432f311fa5a9b34e3b91582db366ad1493f25ea659540f87758ae34678dc864fb2c9d4aba18cb757285292c7d0bac73cc4632a2d54b89f2dc9656d1c50edd49dcbe2102510c70563a96f35dd8a21f0fdc5a1e23ce31fce0ee3023eafdca623508ffd2412fe4dc5b5dd0f75", 16);
            BigInteger Q = new BigInteger("e90a78d5da01e926462e5c17a61ff97b09b6ac18f9137e7b99298705", 16);
            BigInteger G = new BigInteger("9da3567e2f7396dd2ee4716d3477a53a47f811b2275a95ed07024d7231b739c79e88e5377479b23d460a41f981b1af619915e4d8b2dabf2cb716168d02dfb81e76048e23fff6c773f496b2ac3ae06e2eb12c39787a8244452aef404ce631aec9cf4027eefae492ce55517db0af3939354c5414e23205ae3bcd17faedecf80101fa75c619249a43b41aa15ee2d7699ee32e227b641129fe1c78b20c6655b09fa7fead338e179b4b4416c359b16e3773d141e1a876b7ee4281b61120607717f7edc8da8de42b16b54d0802d67d41fc173cd33227436f7c66bd2fe711b37fb0162543c268857414f4188f243fbf92e128388329c9f2df8db4e7808ab539891da798", 16);

            // A Y value that is a valid member of the q-order subgroup for the P/G/Q above
            // (taken from the NIST sample key used in testCombinedTestVector1).
            BigInteger Y = new BigInteger("e485cd4b82e82dafd35f89d40361049e6100c16b17ca156d072832319a40bf7a3f5081182397b8fbd9d33391896bb35d9cc890d8c0a9e5b642b773ce0690f1bbd4596a9604708edb9c27f45117a7395b7407b43eebd8b82bef4a925e2a93185df21fbf012ec9059a9c9efc0b64afe0505aa1864d79a2a9833863c16163b48c9fcc26a9b9e2741097bdeabc2b7208589e4154e1de7ecf77e928668b28abb8113b322c6d426701df979d47ccd50d493b7fb6f20050c3e67cb876c1550d8c8677527600eab07196213252bd9a48d5023788fdb4b65f85144cf6654e092550646be4882125b286ced6578eedc981304ff88725e4138f90a7a4a07c94105d796b038f", 16);

            byte[] seed = Hex.Decode("0102030405060708090a0b0c0d0e0f10");

            // pgenCounter = Integer.MAX_VALUE + 1, i.e. just outside the signed int range.
            BigInteger oversized = BigInteger.ValueOf(int.MaxValue).Add(BigInteger.One);

            try
            {
                DomainParameters dhParams = new DomainParameters(
                    new DerInteger(P),
                    new DerInteger(G),
                    new DerInteger(Q),
                    j: null,
                    new ValidationParams(new DerBitString(seed), new DerInteger(oversized)));
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, dhParams);
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, new DerInteger(Y));

                PublicKeyFactory.CreateKey(spki);

                Assert.Fail("oversized DH pgenCounter accepted");
            }
            catch (ArithmeticException)
            {
                // expected -- DerInteger.IntPositiveValueExact rejects the out-of-range counter
            }
            catch (IOException e)
            {
                Assert.Fail("unexpected IOException for oversized DH pgenCounter: " + e);
            }

            // An in-range pgenCounter must still be accepted and round-trip the exact int value,
            // proving the change is behaviour-preserving for every conforming key.
            int counter = 12345;
            try
            {
                DomainParameters dhParams = new DomainParameters(
                    new DerInteger(P),
                    new DerInteger(G),
                    new DerInteger(Q),
                    j: null,
                    new ValidationParams(new DerBitString(seed), DerInteger.ValueOf(counter)));
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, dhParams);
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, new DerInteger(Y));

                AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(spki);

                DHValidationParameters validation = ((DHPublicKeyParameters)key).Parameters.ValidationParameters;
                if (validation == null || validation.Counter != counter)
                {
                    Assert.Fail("in-range DH pgenCounter not round-tripped");
                }
            }
            catch (IOException e)
            {
                Assert.Fail("unexpected IOException for in-range DH pgenCounter: " + e);
            }
        }

        [Test]
        public void MaliciousMessage()
        {
            // Both peer-supplied values to CalculateAgreement are raised to our (potentially static)
            // private key, so a peer sending a small-order or out-of-range element could mount a
            // small-subgroup confinement attack and recover our private key. Both must be validated as
            // DH public values, even when the other value is well-formed and uses our own parameters.
            DHKeyPairGenerator kpGen = GetDHKeyPairGenerator(g512, p512);
            DHParameters dhParams = ((DHPublicKeyParameters)kpGen.GenerateKeyPair().Public).Parameters;

            DHAgreement dh = new DHAgreement();
            dh.Init(kpGen.GenerateKeyPair().Private);
            dh.CalculateMessage();

            DHPublicKeyParameters goodPub = (DHPublicKeyParameters)kpGen.GenerateKeyPair().Public;
            BigInteger goodMessage = ((DHPublicKeyParameters)kpGen.GenerateKeyPair().Public).Y;

            // p-1 has order 2; it is also out of the accepted (1, p-1) range.
            BigInteger orderTwo = dhParams.P.Subtract(BigInteger.One);

            // A malicious 'message' must be rejected even when 'pub' is well-formed.
            foreach (BigInteger badMessage in new BigInteger[]{ BigInteger.Zero, BigInteger.One, orderTwo, dhParams.P })
            {
                try
                {
                    dh.CalculateAgreement(goodPub, badMessage);
                    Assert.Fail("DHAgreement accepted malicious message " + badMessage);
                }
                catch (ArgumentException)
                {
                    // expected
                }
            }

            // A malicious 'pub' must be rejected even when 'message' is well-formed. DHWeakPubKey passes
            // construction-time validation with a dummy Y, then returns a weak value from the overridden
            // (virtual) Y property -- so CalculateAgreement must re-validate rather than trust the type.
            foreach (BigInteger weakY in new BigInteger[]{ BigInteger.Zero, BigInteger.One, orderTwo, dhParams.P })
            {
                try
                {
                    dh.CalculateAgreement(new DHWeakPubKey(weakY, dhParams), goodMessage);
                    Assert.Fail("DHAgreement accepted malicious public key " + weakY);
                }
                catch (ArgumentException)
                {
                    // expected
                }
            }
        }

        [Test]
        public void ModulusSizeBound()
        {
            // An oversized prime modulus must be rejected at import before the super-linear validation
            // exponentiation, capping the import-time CPU-exhaustion vector. The value is not prime --
            // only its bit length matters to the guard, which fires before any ModPow/Legendre.
            // (bc-csharp DHParameters requires an odd p, so use 2^20000 + 1 rather than bc-java's 2^20000.)
            BigInteger hugeP = BigInteger.One.ShiftLeft(20000).Add(BigInteger.One);

            try
            {
                new DHPublicKeyParameters(BigInteger.Two, new DHParameters(hugeP, BigInteger.Two));
                Assert.Fail("oversized DH modulus accepted");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith("DH modulus out of range"), "unexpected DH message: " + e.Message);
            }

            // A normally-sized modulus is still accepted (q == null, so validation returns after the
            // cheap range check) -- the cap must not reject ordinary keys.
            new DHPublicKeyParameters(BigInteger.Two, new DHParameters(p512, g512));
        }

        [Test, Explicit]
        public void BenchGenerateParameters256() => ImplBenchGenerateParameters(256, 100);

        [Test, Explicit]
        public void BenchGenerateParameters512() => ImplBenchGenerateParameters(512, 100);

        private static DHBasicKeyPairGenerator GetDHBasicKeyPairGenerator(BigInteger g, BigInteger p, int privateValueSize)
        {
            DHParameters dhParams = new DHParameters(p, g, null, privateValueSize);
            DHKeyGenerationParameters dhkgParams = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
            DHBasicKeyPairGenerator kpGen = new DHBasicKeyPairGenerator();
            kpGen.Init(dhkgParams);
            return kpGen;
        }

        private static DHKeyPairGenerator GetDHKeyPairGenerator(BigInteger g, BigInteger p)
        {
            DHParameters dhParams = new DHParameters(p, g);
            DHKeyGenerationParameters dhkgParams = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
            DHKeyPairGenerator kpGen = new DHKeyPairGenerator();
            kpGen.Init(dhkgParams);
            return kpGen;
        }

        private static void ImplBenchGenerateParameters(int size, int count)
        {
            var generator = new DHParametersGenerator();
            generator.Init(size, 100, new SecureRandom());

            for (int i = 0; i < count; ++i)
            {
                generator.GenerateParameters();
            }
        }

        private class DHWeakPubKey
            : DHPublicKeyParameters
        {
            private readonly BigInteger m_weakY;

            internal DHWeakPubKey(BigInteger weakY, DHParameters parameters)
                : base(BigInteger.Two, parameters)
            {
                m_weakY = weakY;
            }

            public override BigInteger Y => m_weakY;
        }
    }
}
