using System;
using System.IO;

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
    /// <summary>Test cases for XmssMTPrivateKeyParameters class.</summary>
    /// <remarks>
    /// <para>
    /// The second half of <see cref="TestPrivateKeySerialisation"/>, through the private key factory, arrives with
    /// the key factories.
    /// </para>
    /// <para>
    /// The methods after <see cref="TestPrivateKeyParsingSha256"/> compare what this key and the engine under it
    /// produce with what bc-java produces for the same seeds.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class XmssMTPrivateKeyTests
    {
        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4 };

        /// <summary>
        /// A stored XMSS^MT private key whose index has been rolled back while its BDS traversal state stayed
        /// advanced is refused at decode: it would otherwise sign a second message under a one-time key already
        /// used (RFC 8391 sec. 1.1), and the signature would verify.
        /// </summary>
        [Test]
        public void TestIndexRollbackRejected()
        {
            int height = 6, layers = 2;
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());

            XmssMTSigner signer = new XmssMTSigner();
            signer.Init(true, kp.Private);
            for (int i = 0; i != 5; i++)
            {
                XmssHarnessTests.Sign(signer, Strings.ToByteArray("message"));
            }
            XmssMTPrivateKeyParameters advanced = (XmssMTPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            Assert.AreEqual(5, advanced.Index);

            byte[] enc = advanced.GetEncoded();

            // the encoding opens with the index, in ceil(totalHeight / 8) octets
            int indexSize = (height + 7) / 8;
            for (int roll = 0; roll != 5; roll++)
            {
                byte[] rolled = Arrays.Clone(enc);
                for (int i = 0; i != indexSize; i++)
                {
                    rolled[i] = 0;
                }
                rolled[indexSize - 1] = (byte)roll;

                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(rolled).Build(),
                    "no exception on index rolled back to " + roll);
                StringAssert.StartsWith("BDS state has wrong index for layer", e.Message);
            }

            // the untouched encoding still decodes, and still signs verifiably
            XmssMTPrivateKeyParameters decoded =
                new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(enc).Build();
            Assert.AreEqual(5, decoded.Index);

            XmssMTSigner s2 = new XmssMTSigner();
            s2.Init(true, decoded);
            byte[] sig = XmssHarnessTests.Sign(s2, Strings.ToByteArray("message"));
            XmssMTSigner v = new XmssMTSigner();
            v.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(v, Strings.ToByteArray("message"), sig));
        }

        /// <summary>
        /// An index outside 0 to maxIndex + 1 is refused whatever the traversal state came from. With a state map
        /// the per-layer check compares only the low bits of each position, so these two indices, 2^h away from
        /// the key's own, agree with the map on every layer and need the bound of their own.
        /// </summary>
        [Test]
        public void TestIndexOutOfRangeRejectedWithAStateMap()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            XmssMTPrivateKeyParameters key =
                (XmssMTPrivateKeyParameters)Generate(parameters, new SecureRandom()).Private;

            XmssEngine.GenerateMTSignature(key, Message);

            long span = 1L << parameters.Height;
            foreach (long index in new long[]{ key.Index - span, key.Index + span })
            {
                XmssMTPrivateKeyParameters.Builder builder = new XmssMTPrivateKeyParameters.Builder(parameters)
                    .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                    .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot())
                    .WithIndex(index).WithBdsState(key.GetBdsState());

                ArgumentException e = Assert.Throws<ArgumentException>(() => builder.Build(), "index " + index);
                Assert.AreEqual("index out of bounds", e.Message);
            }
        }

        /// <summary>
        /// Every index a key can reach still encodes and decodes, and the decoded key still signs verifiably - the
        /// compatibility half of <see cref="TestIndexRollbackRejected"/>. A layer whose leaf index is zero
        /// legitimately carries the previous subtree's final index, and walking the whole key space is what proves
        /// the binding tolerates that one position.
        /// </summary>
        [Test]
        [Explicit] // slow: ~15s
        public void TestEveryIndexRoundTrips()
        {
            int height = 6, layers = 3;
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssMTPrivateKeyParameters key = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTSigner signer = new XmssMTSigner();

            int total = 1 << height;
            for (int i = 0; i != total; i++)
            {
                XmssMTPrivateKeyParameters decoded = new XmssMTPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(key.GetEncoded()).Build();
                Assert.AreEqual(key.Index, decoded.Index);

                XmssMTSigner ds = new XmssMTSigner();
                ds.Init(true, decoded);
                byte[] sig = XmssHarnessTests.Sign(ds, Strings.ToByteArray("message"));
                XmssMTSigner v = new XmssMTSigner();
                v.Init(false, kp.Public);
                Assert.IsTrue(XmssHarnessTests.Verify(v, Strings.ToByteArray("message"), sig), "index " + key.Index);

                if (i == total - 1)
                {
                    break;
                }
                signer.Init(true, key);
                XmssHarnessTests.Sign(signer, Strings.ToByteArray("message"));
                key = (XmssMTPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            }
        }

        /// <summary>
        /// A Java object-serialization gadget in place of the BDS state of an XMSS key is refused, with the codec's
        /// <see cref="IOException"/> as the cause: nothing in this port reads Java serialization at all.
        /// </summary>
        /// <remarks>
        /// The Java method lives in this fixture although it is about an XMSS key. Its second half, the same bytes
        /// through the private key factory, arrives with the key factories.
        /// </remarks>
        [Test]
        public void TestPrivateKeySerialisation()
        {
            string stream =
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArO0ABXNyACJzdW4u"
                + "cm1pLnNlcnZlci5BY3RpdmF0aW9uR3JvdXBJbXBsT+r9SAwuMqcCAARaAA1ncm91cEluYWN0aXZlTAAGYWN0aXZldAAVTGph"
                + "dmEvdXRpbC9IYXNodGFibGU7TAAHZ3JvdXBJRHQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Hcm91cElEO0wA"
                + "CWxvY2tlZElEc3QAEExqYXZhL3V0aWwvTGlzdDt4cgAjamF2YS5ybWkuYWN0aXZhdGlvbi5BY3RpdmF0aW9uR3JvdXCVLvKw"
                + "BSnVVAIAA0oAC2luY2FybmF0aW9uTAAHZ3JvdXBJRHEAfgACTAAHbW9uaXRvcnQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0Fj"
                + "dGl2YXRpb25Nb25pdG9yO3hyACNqYXZhLnJtaS5zZXJ2ZXIuVW5pY2FzdFJlbW90ZU9iamVjdEUJEhX14n4xAgADSQAEcG9y"
                + "dEwAA2NzZnQAKExqYXZhL3JtaS9zZXJ2ZXIvUk1JQ2xpZW50U29ja2V0RmFjdG9yeTtMAANzc2Z0AChMamF2YS9ybWkvc2Vy"
                + "dmVyL1JNSVNlcnZlclNvY2tldEZhY3Rvcnk7eHIAHGphdmEucm1pLnNlcnZlci5SZW1vdGVTZXJ2ZXLHGQcSaPM5+wIAAHhy"
                + "ABxqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN002G0kQxhMx4DAAB4cHcSABBVbmljYXN0U2VydmVyUmVmeAAAFbNwcAAA"
                + "AAAAAAAAcHAAcHBw";

            XmssParameters parameters = new XmssParameters(10, new Sha256Digest());

            byte[] output = Base64.Decode(Strings.ToUtf8ByteArray(stream));

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(output).Build());
            Assert.IsInstanceOf<IOException>(e.InnerException);
        }

        /// <summary>A generated key's encoding reads back to a key that encodes the same.</summary>
        [Test]
        public void TestPrivateKeyParsingSha256()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            byte[] privateKey = ((XmssMTPrivateKeyParameters)kp.Private).GetEncoded();
            byte[] publicKey = ((XmssMTPublicKeyParameters)kp.Public).GetEncoded();

            XmssMTPrivateKeyParameters priv = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privateKey).Build();
            XmssMTPublicKeyParameters pub = new XmssMTPublicKeyParameters.Builder(parameters)
                .WithPublicKey(publicKey).Build();

            Assert.IsTrue(Arrays.AreEqual(priv.GetRoot(), pub.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(priv.GetPublicSeed(), pub.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(privateKey, priv.GetEncoded()));
        }

        /*
         * Java vectors: bc-java e40316b, XMSSEngine.generateMTKeyPair over a SecureRandom handing out 0, 1, 2, ... in
         * turn, then generateMTSignature(key, {1, 2, 3, 4}), extractKeyShard(3), generateMTSignature again, a key
         * recovered through the builder at index 5 from the same seeds, and the key rolled on to its exhausted
         * index. Every key encoding is compared in full - each carries the BDS state map - and each signature by its
         * SHA-256.
         * Index 4 is the first leaf of the second layer-zero subtree, so sig4 and priv5 cover a layer transition.
         */

        [Test]
        public void JavaVectors_Sha256_H4D2()
        {
            CheckJavaVectors(new XmssMTParameters(4, 2, NistObjectIdentifiers.IdSha256), Sha256H4D2Pub,
                Sha256H4D2Priv0, "0e701127b5fd457ff7dcf3f53645e1dca2ba413a2395ade1086eb4316ba7330a",
                Sha256H4D2Priv1, Sha256H4D2Shard, Sha256H4D2Priv4,
                "75c3b7ae428cfbce0eca9119f17ae0f0fa1c519b4ae2d5783a2f1ead6b903686", Sha256H4D2Priv5,
                Sha256H4D2Exhausted);
        }

        [Test]
        public void JavaVectors_Shake256_192_H4D2()
        {
            CheckJavaVectors(new XmssMTParameters(4, 2, NistObjectIdentifiers.IdShake256Len, 24),
                Shake256_192H4D2Pub, Shake256_192H4D2Priv0,
                "69c33cd440c498f83948753e6b8b56d4ddb81fcf0b9f1eb34469ea020aba8bca",
                Shake256_192H4D2Priv1, Shake256_192H4D2Shard, Shake256_192H4D2Priv4,
                "130f6b5d0092cbdf358342ef4d05ed2b17bbeac78b8b3d779fc448ec0ba96661",
                Shake256_192H4D2Priv5, Shake256_192H4D2Exhausted);
        }

        /// <summary>
        /// A registered parameter set carries its four byte identifier in front of the public key, and its private
        /// key's state map holds the top layer's state from generation on.
        /// </summary>
        [Test]
        public void JavaVectors_XmssMTSha2_20_4_256()
        {
            XmssMTParameters parameters = XmssMTParameters.LookupByOid(2);
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters.TreeDigestSize));

            Assert.AreEqual(XmssMTSha2_20_4_256Pub,
                Hex.ToHexString(((XmssMTPublicKeyParameters)kp.Public).GetEncoded()));
            Assert.AreEqual(XmssMTSha2_20_4_256Priv,
                Hex.ToHexString(((XmssMTPrivateKeyParameters)kp.Private).GetEncoded()));

            XmssMTPrivateKeyParameters decoded = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(Hex.Decode(XmssMTSha2_20_4_256Priv)).Build();
            Assert.AreEqual(XmssMTSha2_20_4_256Priv, Hex.ToHexString(decoded.GetEncoded()));
        }

        private static void CheckJavaVectors(XmssMTParameters parameters, string pub, string priv0, string sig0,
            string priv1, string shard, string priv4, string sig4, string priv5, string exhausted)
        {
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters.TreeDigestSize));
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pubKey = (XmssMTPublicKeyParameters)kp.Public;

            Assert.AreEqual(pub, Hex.ToHexString(pubKey.GetEncoded()), "pub");
            Assert.AreEqual(priv0, Hex.ToHexString(priv.GetEncoded()), "priv0");

            byte[] signature0 = XmssEngine.GenerateMTSignature(priv, Message);
            Assert.AreEqual(sig0, XmssTestData.Sha256Hex(signature0), "sig0");
            Assert.AreEqual(priv1, Hex.ToHexString(priv.GetEncoded()), "priv1");
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pubKey, Message, signature0));

            XmssMTPrivateKeyParameters shardKey = priv.ExtractKeyShard(3);
            Assert.AreEqual(shard, Hex.ToHexString(shardKey.GetEncoded()), "shard");
            Assert.AreEqual(priv4, Hex.ToHexString(priv.GetEncoded()), "priv4");

            byte[] signature4 = XmssEngine.GenerateMTSignature(priv, Message);
            Assert.AreEqual(sig4, XmssTestData.Sha256Hex(signature4), "sig4");
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pubKey, Message, signature4));
            Assert.AreEqual(priv5, Hex.ToHexString(priv.GetEncoded()), "priv5");

            // recovery through the builder at an index, which walks the hypertree to it
            XmssMTPrivateKeyParameters recovered = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithIndex(5).Build();
            Assert.AreEqual(priv5, Hex.ToHexString(recovered.GetEncoded()), "rec5");
            Assert.AreEqual(priv, recovered);

            for (int i = 0; i != 11; i++)
            {
                priv.RollKey();
            }
            Assert.AreEqual(16, priv.Index);
            Assert.AreEqual(exhausted, Hex.ToHexString(priv.GetEncoded()), "exhausted");

            // and the Java encodings read back to keys that encode the same
            foreach (string encoding in new string[]{ priv0, priv1, shard, priv4, priv5, exhausted })
            {
                XmssMTPrivateKeyParameters decoded = new XmssMTPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Hex.Decode(encoding)).Build();
                Assert.AreEqual(encoding, Hex.ToHexString(decoded.GetEncoded()));
            }
        }

        private static SecureRandom CountingRandom(int n)
        {
            byte[] data = new byte[3 * n];
            for (int i = 0; i != data.Length; i++)
            {
                data[i] = (byte)i;
            }
            return FixedSecureRandom.From(data);
        }

        private static AsymmetricCipherKeyPair Generate(XmssMTParameters parameters, SecureRandom random)
        {
            XmssMTKeyPairGenerator kpGen = new XmssMTKeyPairGenerator();
            kpGen.Init(new XmssMTKeyGenerationParameters(random, parameters));
            return kpGen.GenerateKeyPair();
        }

        private const string Sha256H4D2Pub =
            "cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d204237621799404142434445464748494a4b4c4d4e4f" +
            "505152535455565758595a5b5c5d5e5f";

        private const string Sha256H4D2Priv0 =
            "00000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0f00000001000000010000000200000002000000030000000000010000000200000020cf4057feb3275804643c06acdf" +
            "b79de6a4eacb58b0f5791c7b9d20423762179900000002000000000000002033f925bca69b9e81c6153d57b8346b23cc" +
            "eca97a2b851b81f598b06e6b1144140000000100000020403421e4177823bbbc1b3c7056f9a5949f7d5721fecad65c64" +
            "ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e637d92ff2794e16d2c827dffe463f" +
            "3f2f328b903f5c0375f64c000000000000000000000000d5b3b5df42b369e4a18aad21baf4275a43b35d763eca77284f" +
            "12c83703a745f9";

        private const string Sha256H4D2Priv1 =
            "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0f00000002000000000000000200000002000000030000000100010000000200000020459a423afd247679ab8102df23" +
            "c4e781f3a8df70a3d54403bffbed62bce8d3730000000200000000000000200c9f44bad769c5866af8d63b5f84adaa6a" +
            "404aacddef42ebc96f7e9f7460b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d407" +
            "21e9059be195f500000001000000000000000100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a611" +
            "5417692b8fd580680ab2180000000000000000000000010000000000000000000000202caf15d3d48449094727d18cab" +
            "e762d012b82643b52ddbeed788b06e37bb91630000000100000002000000020000000300000000000100000002000000" +
            "20cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179900000002000000000000002033f925" +
            "bca69b9e81c6153d57b8346b23cceca97a2b851b81f598b06e6b1144140000000100000020403421e4177823bbbc1b3c" +
            "7056f9a5949f7d5721fecad65c64ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e6" +
            "37d92ff2794e16d2c827dffe463f3f2f328b903f5c0375f64c00000000000000000000000097195a6d78234c5c77c320" +
            "49afd776f9a68a466dfccf0210c813d2fe9b7917dc";

        private const string Sha256H4D2Shard =
            "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0300000002000000000000000200000002000000030000000100010000000200000020459a423afd247679ab8102df23" +
            "c4e781f3a8df70a3d54403bffbed62bce8d3730000000200000000000000200c9f44bad769c5866af8d63b5f84adaa6a" +
            "404aacddef42ebc96f7e9f7460b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d407" +
            "21e9059be195f500000001000000000000000100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a611" +
            "5417692b8fd580680ab2180000000000000000000000010000000000000000000000202caf15d3d48449094727d18cab" +
            "e762d012b82643b52ddbeed788b06e37bb91630000000100000002000000020000000300000000000100000002000000" +
            "20cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179900000002000000000000002033f925" +
            "bca69b9e81c6153d57b8346b23cceca97a2b851b81f598b06e6b1144140000000100000020403421e4177823bbbc1b3c" +
            "7056f9a5949f7d5721fecad65c64ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e6" +
            "37d92ff2794e16d2c827dffe463f3f2f328b903f5c0375f64c0000000000000000000000004276efb04fa0b5cdb0fc86" +
            "fd1c1c27a73b3ebc1e2f786349279d614e6feb9804";

        private const string Sha256H4D2Priv4 =
            "04000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0f00000002000000000000000200000002000000030000000300010000000200000020459a423afd247679ab8102df23" +
            "c4e781f3a8df70a3d54403bffbed62bce8d373000000020000000000000020f47cf5e9da530e2e7f8f416c56501f10da" +
            "566960db66f6bbed631df531969a6100000001000000206b070e08b3e8ab0b3fba824a35eaeff86ec5c0818ee034be8c" +
            "2ce282be33ed800000000100000000000000000000000000000000000000000000000100000002000000020000000300" +
            "00000100010000000200000020cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d204237621799000000" +
            "020000000000000020fdc539c5013b0318fb567893ac83e6ca40d39ebb477d2a2a16ef50935b6b323800000001000000" +
            "20403421e4177823bbbc1b3c7056f9a5949f7d5721fecad65c64ea4f7b64fb7369000000010000000000000001000000" +
            "0000000020e12c101fd563e637d92ff2794e16d2c827dffe463f3f2f328b903f5c0375f64c0000000000000000000000" +
            "0100000000000000000000002033f925bca69b9e81c6153d57b8346b23cceca97a2b851b81f598b06e6b114414d9d4ef" +
            "6c9dd7e325855269b07706eb041137ac0048b70300ef4c1d5b98661d7c";

        private const string Sha256H4D2Priv5 =
            "05000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0f00000002000000000000000200000002000000030000000100010000000200000020d0a45fea03c7dd7d23ef70220c" +
            "2fef542562b54fc3278146dca6e28175c68fd9000000020000000000000020fa43b24d6ff309db5f3d4f1c3e7cd5898e" +
            "92e8e9cd837cfb35631eac6f44da930000000100000020945e8dae08dfb431ed428173c473a77ceb1f54a6182d78b940" +
            "9abd4c0d0830640000000100000000000000010000000000000020b09f83bc26c36611bfbb9f3959bc2cee86c1d55018" +
            "27e1d6703c8e97769568c70000000000000000000000010000000000000000000000202e8c1b719052b12a9f842d4931" +
            "63ef0995789c7efe005e7ef7ae81dc3f74ba420000000100000002000000020000000300000001000100000002000000" +
            "20cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d204237621799000000020000000000000020fdc539" +
            "c5013b0318fb567893ac83e6ca40d39ebb477d2a2a16ef50935b6b32380000000100000020403421e4177823bbbc1b3c" +
            "7056f9a5949f7d5721fecad65c64ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e6" +
            "37d92ff2794e16d2c827dffe463f3f2f328b903f5c0375f64c0000000000000000000000010000000000000000000000" +
            "2033f925bca69b9e81c6153d57b8346b23cceca97a2b851b81f598b06e6b114414c76c6f44c896647f8087d2ce6b9156" +
            "d155ef693692c27c9146630f7a512ae1f0";

        private const string Sha256H4D2Exhausted =
            "10000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e" +
            "5fcf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179942444d000000000100000000000000" +
            "0f0000000020260c6b2856fb14c3d714b52661b77223d84eac851fae6620d7548fffaf5c7b";

        private const string Shake256_192H4D2Pub =
            "afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad1873f303132333435363738393a3b3c3d3e3f4041424344454647";

        private const string Shake256_192H4D2Priv0 =
            "00000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000f00000001000000010000000200000002000000030000000000010000000200" +
            "000018afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad1873f000000020000000000000018d3bcdce27b4f31ec13" +
            "fa74fd23369a93a1a5eb612cc5a4f20000000100000018c29efb66d1d22df9c5ef1782b4da172c85e0d0b1ae491e3800" +
            "000001000000000000000100000000000000188a64513582c31dea0443ceaf34b3faf76630441977c9a2540000000000" +
            "00000000000000e1abec3cdd547e83213a199ba294b90bd82533ee78e62721f21b569806bf7cd8";

        private const string Shake256_192H4D2Priv1 =
            "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000f00000002000000000000000200000002000000030000000100010000000200" +
            "0000186a11c6b653e068d6198a7d3d164ddd848e2f4bcf9105654e0000000200000000000000181ef069c12d0b56f113" +
            "af21b90c40fdd6bab1b7cf89a8eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800" +
            "00000100000000000000010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dcdbe5eb38bb0000000000" +
            "000000000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba560000000100" +
            "00000200000002000000030000000000010000000200000018afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f000000020000000000000018d3bcdce27b4f31ec13fa74fd23369a93a1a5eb612cc5a4f20000000100000018c29efb" +
            "66d1d22df9c5ef1782b4da172c85e0d0b1ae491e3800000001000000000000000100000000000000188a64513582c31d" +
            "ea0443ceaf34b3faf76630441977c9a254000000000000000000000000152f16afa13f4011db6be6942c3888cfc9e1b7" +
            "e82a89bc965b4b1e90eb648b98";

        private const string Shake256_192H4D2Shard =
            "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000300000002000000000000000200000002000000030000000100010000000200" +
            "0000186a11c6b653e068d6198a7d3d164ddd848e2f4bcf9105654e0000000200000000000000181ef069c12d0b56f113" +
            "af21b90c40fdd6bab1b7cf89a8eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800" +
            "00000100000000000000010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dcdbe5eb38bb0000000000" +
            "000000000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba560000000100" +
            "00000200000002000000030000000000010000000200000018afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f000000020000000000000018d3bcdce27b4f31ec13fa74fd23369a93a1a5eb612cc5a4f20000000100000018c29efb" +
            "66d1d22df9c5ef1782b4da172c85e0d0b1ae491e3800000001000000000000000100000000000000188a64513582c31d" +
            "ea0443ceaf34b3faf76630441977c9a25400000000000000000000000055b40550650e044b1d64c61611aa657d9bbc90" +
            "3e00890622e1dfc09745a19a12";

        private const string Shake256_192H4D2Priv4 =
            "04000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000f00000002000000000000000200000002000000030000000300010000000200" +
            "0000186a11c6b653e068d6198a7d3d164ddd848e2f4bcf9105654e000000020000000000000018c50ad87b83c3b79a45" +
            "563cf754897e9a4b98f6f9773025a00000000100000018f32960774963a4d9b1240fcf7509d3a6f1de44114c063ce900" +
            "000001000000000000000000000000000000000000000000000001000000020000000200000003000000010001000000" +
            "0200000018afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad1873f000000020000000000000018b4af1e586d6323" +
            "6df013fee56ea760445f31dff64432b1460000000100000018c29efb66d1d22df9c5ef1782b4da172c85e0d0b1ae491e" +
            "3800000001000000000000000100000000000000188a64513582c31dea0443ceaf34b3faf76630441977c9a254000000" +
            "000000000000000001000000000000000000000018d3bcdce27b4f31ec13fa74fd23369a93a1a5eb612cc5a4f2458e64" +
            "4ce77a88d8b3f274bfbfb23ccb51e4f2247f444b8145e04bf29ffab41a";

        private const string Shake256_192H4D2Priv5 =
            "05000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000f00000002000000000000000200000002000000030000000100010000000200" +
            "000018329f519508aa5c5cbeb63d6289963228208108fc241ad86b000000020000000000000018ff8aca99c6aaf680b2" +
            "8c18172cf12713877ecea558caa5dd0000000100000018624ef9416b990e44c8e762580b885140874f35a87501599400" +
            "00000100000000000000010000000000000018aa7c2c22b67f928d367add1af7a9ef081249b67569c7cbae0000000000" +
            "000000000000010000000000000000000000186dd576e64de86d544baefb52a81120d0fd5a1925067986170000000100" +
            "00000200000002000000030000000100010000000200000018afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f000000020000000000000018b4af1e586d63236df013fee56ea760445f31dff64432b1460000000100000018c29efb" +
            "66d1d22df9c5ef1782b4da172c85e0d0b1ae491e3800000001000000000000000100000000000000188a64513582c31d" +
            "ea0443ceaf34b3faf76630441977c9a254000000000000000000000001000000000000000000000018d3bcdce27b4f31" +
            "ec13fa74fd23369a93a1a5eb612cc5a4f2a218a6597b3d25bc51f8837e3352d7b2fc5fb92ffe8dc2f7a30872b3df9d96" +
            "73";

        private const string Shake256_192H4D2Exhausted =
            "10000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e" +
            "2f303132333435363738393a3b3c3d3e3f4041424344454647afeb13fa5de9505d5f2c747ee270c6bccb9637e06ad187" +
            "3f42444d0000000001000000000000000f00000000fe9da593b437dac5fdc866f725d870e87115b023cac25720372baf" +
            "0557757aac";

        private const string XmssMTSha2_20_4_256Pub =
            "00000002e9faa5638cf84a5f2c66b9a8041f90ff2950b44aa01c381b06d89cfb0e8ce4de404142434445464748494a4b" +
            "4c4d4e4f505152535455565758595a5b5c5d5e5f";

        private const string XmssMTSha2_20_4_256Priv =
            "000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c" +
            "2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c" +
            "5d5e5fe9faa5638cf84a5f2c66b9a8041f90ff2950b44aa01c381b06d89cfb0e8ce4de42444d00000000010000000000" +
            "0fffff000000010000000300000005000000030000001f0000000000010000000500000020e9faa5638cf84a5f2c66b9" +
            "a8041f90ff2950b44aa01c381b06d89cfb0e8ce4de0000000500000000000000205c21d4a50ea036801ab575aba6682f" +
            "904f2f7b28c26070ed0626b34df2aed2ed00000001000000205e514ffb510a08a78617aa5a09687913e9212a9c5ce9a5" +
            "2375b0922303d7bec8000000020000002027564698e7a97ce6b34ef379ab498b8a23f46a0afe1996c8d8a831aa20e59e" +
            "ca00000003000000204b02756caa46ce739b1c8f3c39da4e3fa5f7b11ac103b62c120ecae3e0c053c600000004000000" +
            "200413f59abda6d20b10bd7b58caf45091b22f50f1137a73890e5442aec22fd471000000020000000200000003000000" +
            "020000002039107a991979a9c25a181bb952f85e158c0cda48cf8bea52dd8176ed30d415b000000002000000207321fa" +
            "cd1d4e96cd6390ef08df2c5d3f34f18a8dd53597ad720aedcb9ab3698300000002000000200e9b8d3bbe57559290acc0" +
            "e194da448f9554ebdd4b4ece5fd63175b20fc29b4500000003000000010000000300000020831d56af3417153f2d5914" +
            "ce06045ab90e9f74089dc59ff02c2d6f7d5fdb12a5000000000000000200000000000000000000000000010100000000" +
            "00000020f472c476513f88d2e6a6f4d67cb7c21991e747af740353ae9d918b17bd416c98000000010000000100000000" +
            "00010100000001000000201b531774bcb60c78a13d3b94a67bd7655cd8c40ed302f2dbbdc82abb2fe9adcb00000000e9" +
            "b8d44739792ebd479d501399a17fa4d250dbb699f9fbf383c9d4f9a004fa72";
    }
}
