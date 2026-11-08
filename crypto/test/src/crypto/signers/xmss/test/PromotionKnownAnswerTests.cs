using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Known answers bc-java recorded from the XMSS implementation its current one was promoted from: SHA-256
    /// digests of the key and signature encodings it produced from fixed seeds. They pin what a round trip cannot -
    /// the truncating branch of the keyed hash functions (XMSS-SHA2_10_192, whose n is shorter than the digest's
    /// output), and the idx_sig bytes of the H_msg key, which are all zeros at index 0 and show only by signing at
    /// every index of a key.
    /// </summary>
    /// <remarks>
    /// The key encodings Java checks here are SubjectPublicKeyInfo and PrivateKeyInfo, and arrive with the key
    /// factories, together with the XMSSMT-SHA2_20/2_256 set, which Java checks for its encodings alone. Their vectors
    /// are kept here so the table matches Java's.
    /// </remarks>
    [TestFixture]
    public class PromotionKnownAnswerTests
    {
        private static readonly byte[] Message = Strings.ToByteArray("the quick brown fox jumped over the lazy dog");

        private static readonly string[][] Vectors = {
            new string[]{ "XMSS h4/0", "pub", "ce4406b5b89cbaa66b6623dfc14deb5fefad6360ecbe9cc2204b4cd8f15e4203" },
            new string[]{ "XMSS h4/0", "priv", "06eeae237d8b99eb72ca272c9e4564ea2d3031eff62f8b715613042b568c8c90" },
            new string[]{ "XMSS h4/0", "sig", "0ea6d588a11e817ee3417e22d12822377a4321306802d6ea9c90b5aa956452c7" },
            new string[]{ "XMSS h4/1", "pub", "f074b48ae2ee91b411708a51dcd41e63b9c13f9debac6b6853bd35f3039bbaa2" },
            new string[]{ "XMSS h4/1", "priv", "b88570e9ad602c8f8a8fa389478e2a1c5d62eae827688dac5a7bea18635f7127" },
            new string[]{ "XMSS h4/1", "sig", "b9dc894a83015b16dc5c4116d097a61b38c70866d3fb59f2fd137f8461a3eca9" },
            new string[]{ "XMSS h4/2", "pub", "4551b19b0a1370c74d7ea896923f9821f2da3c45828f16ea56a0784fdbb09f5a" },
            new string[]{ "XMSS h4/2", "priv", "6eaf2d96e1e88d29cb78bb75cf049ea8b2087c2c175e490db64c34bf63f962a1" },
            new string[]{ "XMSS h4/2", "sig", "6648f1f5db96c36136eb588b3545a9632477d098936df4239384fab683c8ee53" },
            new string[]{ "XMSS h4/3", "pub", "fbf5c442bb06505307f3cf54cb32ee55b536a271cb805ddcc5c1600ca1fea4ff" },
            new string[]{ "XMSS h4/3", "priv", "97ee527f3a67da85af0cd08e6c7d3c46fedc58d0599a066ae022399bb8fb2cfe" },
            new string[]{ "XMSS h4/3", "sig", "153019ff13063a5cc243e5701428896a37a12d6e01d8ffe3bb4fe503963d0a94" },
            new string[]{ "XMSS-SHA2_10_256", "pub",
                "0e1451fbae7108893776abb1d0e0b63816d9d49f21f0971531cf73cab4ffc664" },
            new string[]{ "XMSS-SHA2_10_256", "priv",
                "5b9771bf00119bc8b312d55f712ea5d5f0bd0b28453b03cad101d05b3605c6a4" },
            new string[]{ "XMSS-SHA2_10_256", "sig",
                "3db94d6fde04c1c97c9ac3495f817c4445cdc9846f64ef56ddd28f720eb77104" },
            new string[]{ "XMSS-SHAKE256_10_192", "pub",
                "dfb6d56fca58a41a08f2e57b3ebc2a7d7634ec871033c2d6efd01870227e7f3e" },
            new string[]{ "XMSS-SHAKE256_10_192", "priv",
                "548a5f76c3fcc8ba13e8feb76faebfd085fe41fd0772243522b7ddc6f5db26e9" },
            new string[]{ "XMSS-SHAKE256_10_192", "sig",
                "4aeba363fb045547fb167bec48a9621d18e1d77777af5a458b283e79e7f50757" },
            new string[]{ "XMSS-SHA2_10_192", "pub",
                "5c8170f3c76a354dedbc220d83eda14b4b8d9bc56e14473ee678de64b263c813" },
            new string[]{ "XMSS-SHA2_10_192", "priv",
                "065efcfcb6e2b2d29eb97173cc5dc75b7608a89c447916f5d7e86e00b93ae231" },
            new string[]{ "XMSS-SHA2_10_192", "sig",
                "b5c1968e0582c96fbffc5392643fc6b6dcdd51865942db128c4af72ddff52f18" },
            new string[]{ "XMSSMT-SHA2_20/2_256", "pub",
                "b70f6e7ac29ada1b189cf966b16d997572d2a042d4e4e09cd915a4ee7a42f529" },
            new string[]{ "XMSSMT-SHA2_20/2_256", "priv",
                "4ca7faa3577eb3eaedfb39491b987c12a17c5a8ed134618a5b4c28d9e000d829" },
            new string[]{ "XMSSMT h4d2/0", "pub", "faaeee5ff11087b25f6cfb6a98e6736258ecc3072012dd99360975a2dce03326" },
            new string[]{ "XMSSMT h4d2/0", "priv", "a8c4903b6b8efde72730dd2ae6eb516c3a43e276d10d388580f4b237c795d9ec" },
            new string[]{ "XMSSMT h4d2/0", "sig", "b35a9b452ef0dfd8245c20f124f85655f023cb606e3669e11934bbd23a4183cd" },
            new string[]{ "XMSSMT h4d2/1", "pub", "68cccbb5ea3c05ca141f53dd2a8f6bf48107b76849f8753d76edb24e0d53a9c9" },
            new string[]{ "XMSSMT h4d2/1", "priv", "f1de29988552d42830d53c01c51df1862904545fb449f82a60d59a3f78f089ec" },
            new string[]{ "XMSSMT h4d2/1", "sig", "1e2a376722c69795d342de555cbdbf741acdac0e83f1de1d2a442f19467e1781" },
            new string[]{ "XMSSMT h4d2/2", "pub", "1f9a5445c07a0d68b0c3051ec678beded0f153eb2016bede2eeba716ba5054cb" },
            new string[]{ "XMSSMT h4d2/2", "priv", "054105e5022b4779549fa2bcab69ee53c9d6a84bddbf31448e45c289bdfc0876" },
            new string[]{ "XMSSMT h4d2/2", "sig", "e6e0f0ca6a41d452f7ed6403f2f42ae45b1883a406b84d01d8013cd764b7a158" },
            new string[]{ "XMSSMT h4d2/3", "pub", "c9ec1ad96417d62cd425d370bc07c94bd9cc84b87ad63059bcb617c3f7ef232b" },
            new string[]{ "XMSSMT h4d2/3", "priv", "d7ec952c5d47f879d70d3410ecaac1ab49215bf859d709a4d6dc3491126ad42b" },
            new string[]{ "XMSSMT h4d2/3", "sig", "a5ba579595a6537dcbe49a6ea10ec1911c53101657e12c1b84999cdbd8724412" },
            new string[]{ "XMSS h4/0 every index", "sigs",
                "db4ed4b8404dd238bae9df783759719361072b5585de27ba32e3935c8996f99e" },
            new string[]{ "XMSSMT h4d2/0 every index", "sigs",
                "c3b5fb018973b031218b0ed3e4bf0f43e050c3338970105359830d3ebd5de753" },
        };

        /// <remarks>XMSS half: the SubjectPublicKeyInfo / PrivateKeyInfo checks arrive with the key factories.
        /// </remarks>
        [Test]
        public void TestXmssKeysAndSignatures()
        {
            for (int i = 0; i != 4; i++)
            {
                CheckXmss("XMSS h4/" + i, new XmssParameters(4, Digest(i)), SeedFor(i));
            }
        }

        /// <remarks>XMSS half: the key encoding checks and the XMSS^MT set arrive later.</remarks>
        [Test]
        [Explicit] // slow: ~78s
        public void TestStandardParameterSets()
        {
            CheckXmss("XMSS-SHA2_10_256", new XmssParameters(10, new Sha256Digest()), SeedFor(10));
            CheckXmss("XMSS-SHAKE256_10_192", new XmssParameters(10, NistObjectIdentifiers.IdShake256Len, 24),
                SeedFor(11));
            CheckXmss("XMSS-SHA2_10_192", new XmssParameters(10, NistObjectIdentifiers.IdSha256, 24), SeedFor(12));
        }

        /// <remarks>The SubjectPublicKeyInfo / PrivateKeyInfo checks arrive with the key factories.</remarks>
        [Test]
        public void TestXmssMTKeysAndSignatures()
        {
            for (int i = 0; i != 4; i++)
            {
                string label = "XMSSMT h4d2/" + i;
                AsymmetricCipherKeyPair kp = XmssMtKey(new XmssMTParameters(4, 2, Digest(i)), SeedFor(20 + i));

                XmssMTSigner signer = new XmssMTSigner();
                signer.Init(true, kp.Private);
                byte[] sig = XmssHarnessTests.Sign(signer, Message);
                Assert.AreEqual(Expected(label, "sig"), Sha256(sig), label + ": signature");

                XmssMTSigner verifier = new XmssMTSigner();
                verifier.Init(false, kp.Public);
                Assert.IsTrue(XmssHarnessTests.Verify(verifier, Message, sig), label + ": signature did not verify");
            }
        }

        [Test]
        public void TestSignaturesAtEveryIndexOfAKey()
        {
            XmssSigner signer = new XmssSigner();
            signer.Init(true, XmssKey(new XmssParameters(4, Digest(0)), SeedFor(30)).Private);

            Sha256Digest all = new Sha256Digest();
            for (int i = 0; i != 1 << 4; i++)
            {
                byte[] sig = XmssHarnessTests.Sign(signer, Message);
                all.BlockUpdate(sig, 0, sig.Length);
            }
            Assert.AreEqual(Expected("XMSS h4/0 every index", "sigs"), DoFinal(all),
                "XMSS: signatures over every index");

            XmssMTSigner mtSigner = new XmssMTSigner();
            mtSigner.Init(true, XmssMtKey(new XmssMTParameters(4, 2, Digest(0)), SeedFor(31)).Private);

            all = new Sha256Digest();
            for (int i = 0; i != 1 << 4; i++)
            {
                byte[] sig = XmssHarnessTests.Sign(mtSigner, Message);
                all.BlockUpdate(sig, 0, sig.Length);
            }
            Assert.AreEqual(Expected("XMSSMT h4d2/0 every index", "sigs"), DoFinal(all),
                "XMSS^MT: signatures over every index");
        }

        /// <summary>
        /// A message streamed in must sign and verify, and the buffer is consumed by each operation rather than
        /// carried into the next.
        /// </summary>
        [Test]
        public void TestStreamingRoundTrip()
        {
            AsymmetricCipherKeyPair kp = XmssKey(new XmssParameters(4, new Sha256Digest()), SeedFor(7));

            XmssSigner signer = new XmssSigner();
            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);
            byte[] streamed = signer.GenerateSignature();

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(verifier.VerifySignature(streamed),
                "streamed signature did not verify through the streaming path");

            // VerifySignature() consumed the buffer, so feeding the same message again verifies the message alone
            // and not the message twice
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(verifier.VerifySignature(streamed), "second streamed verification failed");
        }

        /// <summary>
        /// The randomizer is derived from the key (RFC 8391 sec. 4.1.9), so a random supplied through
        /// <see cref="ParametersWithRandom"/> has nothing to drive: the signature is byte-identical to the one signed
        /// without the wrapper.
        /// </summary>
        [Test]
        public void TestParametersWithRandomAcceptedForSigning()
        {
            // a random that would be impossible to miss had any of it reached the signature
            SecureRandom random = FixedSecureRandom.From(new byte[256]);

            XmssParameters parameters = new XmssParameters(4, Digest(0));
            byte[] seed = SeedFor(31);

            XmssSigner wrappedSigner = new XmssSigner();
            wrappedSigner.Init(true, new ParametersWithRandom(XmssKey(parameters, seed).Private, random));
            byte[] wrapped = XmssHarnessTests.Sign(wrappedSigner, Message);

            XmssSigner plainSigner = new XmssSigner();
            plainSigner.Init(true, XmssKey(parameters, seed).Private);
            Assert.IsTrue(Arrays.AreEqual(wrapped, XmssHarnessTests.Sign(plainSigner, Message)),
                "XMSS: ParametersWithRandom changed the signature");

            XmssMTParameters mtParams = new XmssMTParameters(4, 2, Digest(0));
            byte[] mtSeed = SeedFor(32);

            XmssMTSigner wrappedMtSigner = new XmssMTSigner();
            wrappedMtSigner.Init(true, new ParametersWithRandom(XmssMtKey(mtParams, mtSeed).Private, random));
            byte[] mtWrapped = XmssHarnessTests.Sign(wrappedMtSigner, Message);

            XmssMTSigner plainMtSigner = new XmssMTSigner();
            plainMtSigner.Init(true, XmssMtKey(mtParams, mtSeed).Private);
            Assert.IsTrue(Arrays.AreEqual(mtWrapped, XmssHarnessTests.Sign(plainMtSigner, Message)),
                "XMSS^MT: ParametersWithRandom changed the signature");
        }

        private static void CheckXmss(string label, XmssParameters parameters, byte[] seed)
        {
            AsymmetricCipherKeyPair kp = XmssKey(parameters, seed);

            XmssSigner signer = new XmssSigner();
            signer.Init(true, kp.Private);
            byte[] sig = XmssHarnessTests.Sign(signer, Message);
            Assert.AreEqual(Expected(label, "sig"), Sha256(sig), label + ": signature");

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, Message, sig), label + ": signature did not verify");
        }

        private static string Expected(string label, string what)
        {
            for (int i = 0; i != Vectors.Length; i++)
            {
                if (Vectors[i][0].Equals(label) && Vectors[i][1].Equals(what))
                    return Vectors[i][2];
            }
            throw new InvalidOperationException("no vector for " + label + " " + what);
        }

        private static string Sha256(byte[] data)
        {
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            return DoFinal(digest);
        }

        private static string DoFinal(Sha256Digest digest)
        {
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            return Hex.ToHexString(output);
        }

        private static AsymmetricCipherKeyPair XmssKey(XmssParameters parameters, byte[] seed)
        {
            XmssKeyPairGenerator gen = new XmssKeyPairGenerator();
            gen.Init(new XmssKeyGenerationParameters(FixedRandom(seed), parameters));
            return gen.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair XmssMtKey(XmssMTParameters parameters, byte[] seed)
        {
            XmssMTKeyPairGenerator gen = new XmssMTKeyPairGenerator();
            gen.Init(new XmssMTKeyGenerationParameters(FixedRandom(seed), parameters));
            return gen.GenerateKeyPair();
        }

        private static IDigest Digest(int n)
        {
            switch (n)
            {
            case 0:
                return new Sha256Digest();
            case 1:
                return new ShakeDigest(128);
            case 2:
                return new Sha512Digest();
            default:
                return new ShakeDigest(256);
            }
        }

        private static byte[] SeedFor(int n)
        {
            byte[] seed = new byte[64];
            for (int i = 0; i != seed.Length; i++)
            {
                seed[i] = (byte)(n * 31 + i);
            }
            return seed;
        }

        private static SecureRandom FixedRandom(byte[] seed)
        {
            // key generation reads three tree-digest-sized blocks (3 * 64 at the largest parameter set)
            byte[] material = new byte[6 * seed.Length];
            for (int i = 0; i != 6; i++)
            {
                Array.Copy(seed, 0, material, i * seed.Length, seed.Length);
            }

            return FixedSecureRandom.From(material);
        }
    }
}
