using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// PKCS#8 PrivateKeyInfo round trips for XMSS / XMSS^MT (bc-java github #2176). Every standard (RFC 8391 /
    /// SP 800-208) parameter set is encoded under the RFC 9802 OID (id-alg-xmss-hashsig / id-alg-xmssmt-hashsig) that
    /// the matching SubjectPublicKeyInfo uses, in bc-java's private key encoding, so a key pair's private and public
    /// halves share one algorithm OID and a private key round-trips to its exact parameter set, n included.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The six Java methods each generate a key over a height 10 tree, which is slow here, so they are explicit;
    /// <see cref="XmssMtSp800208_20_4_192PrivateKeyRoundTrip"/> runs the same check by default on the two
    /// SP 800-208 n = 24 XMSS^MT sets whose layers are height 5.
    /// </para>
    /// <para>
    /// <see cref="JavaVectors"/> are bc-java e40316b encodings, made with a key pair generator fed the bytes 0, 1, 2,
    /// ... as its randomness: the SubjectPublicKeyInfo, the PrivateKeyInfo after three signatures of {1, 2, 3, 4}
    /// through the signer, a two-use shard taken from that key, the PrivateKeyInfo of the key left at index 5, and
    /// the SHA-256 of the signature that key then makes. The XMSSMT-SHA2_20/4_256 private key encodings are too long
    /// to keep inline and are loaded from <c>crypto/test/data/xmss/</c>.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class XmssPrivateKeyEncodingTests
    {
        // RFC 8391 sets.
        private const int XmssSha2_10_256 = 0x00000001;    // SHA-256/256, n=32
        private const int XmssMTSha2_20_2_256 = 0x00000001; // SHA-256/256, 20/2, n=32

        // SP 800-208 sets.
        private const int XmssSha2_10_192 = 0x0000000d;    // SHA-256/192, n=24
        private const int XmssShake256_10_192 = 0x00000013; // SHAKE256/192, n=24, id-shake256-len
        private const int XmssMTSha2_20_2_192 = 0x00000021;    // SHA-256/192, n=24
        private const int XmssMTShake256_20_2_192 = 0x00000031; // SHAKE256/192, n=24, id-shake256-len
        private const int XmssMTSha2_20_4_192 = 0x00000022;    // SHA-256/192, 20/4, n=24
        private const int XmssMTShake256_20_4_192 = 0x00000032; // SHAKE256/192, 20/4, n=24, id-shake256-len

        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4 };

        [Test]
        [Explicit] // slow: ~14s
        public void TestXmssRfc8391SetSharesRfc9802Oid() => CheckXmss(XmssSha2_10_256, 32);

        [Test]
        [Explicit] // slow: ~10s
        public void TestXmssSha256_192PrivateKeyRoundTrip() => CheckXmss(XmssSha2_10_192, 24);

        [Test]
        [Explicit] // slow: ~13s
        public void TestXmssShake256_192PrivateKeyRoundTrip() => CheckXmss(XmssShake256_10_192, 24);

        [Test]
        [Explicit] // slow: ~21s
        public void TestXmssMtRfc8391SetSharesRfc9802Oid() => CheckXmssMt(XmssMTSha2_20_2_256, 32);

        [Test]
        [Explicit] // slow: ~12s
        public void TestXmssMtSha256_192PrivateKeyRoundTrip() => CheckXmssMt(XmssMTSha2_20_2_192, 24);

        [Test]
        [Explicit] // slow: ~15s
        public void TestXmssMtShake256_192PrivateKeyRoundTrip() => CheckXmssMt(XmssMTShake256_20_2_192, 24);

        /// <summary>The Java methods' check, on the SP 800-208 n = 24 XMSS^MT sets with height 5 layers.</summary>
        [Test]
        public void XmssMtSp800208_20_4_192PrivateKeyRoundTrip()
        {
            CheckXmssMt(XmssMTSha2_20_4_192, 24);
            CheckXmssMt(XmssMTShake256_20_4_192, 24);
        }

        /// <summary>
        /// The encodings this port writes are bc-java's, byte for byte, for every key it can generate quickly from
        /// the same randomness; and every one of bc-java's encodings reads back to a key that writes it again
        /// unchanged.
        /// </summary>
        [Test]
        public void JavaVectors_Encodings()
        {
            foreach (string[] vector in JavaVectors)
            {
                string label = vector[0];

                AsymmetricCipherKeyPair kp = GenerateCounting(label);
                if (kp != null)
                {
                    byte[] spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public).GetEncoded();
                    Assert.AreEqual(vector[1], Hex.ToHexString(spki), label + " spki");

                    AsymmetricKeyParameter priv = SignThrice(kp.Private);
                    Assert.AreEqual(vector[2], Pkcs8(priv), label + " pkcs8 at 3");

                    AsymmetricKeyParameter shard = (priv is XmssPrivateKeyParameters xmss)
                        ? (AsymmetricKeyParameter)xmss.ExtractKeyShard(2)
                        : ((XmssMTPrivateKeyParameters)priv).ExtractKeyShard(2);
                    Assert.AreEqual(vector[3], Pkcs8(shard), label + " shard");
                    Assert.AreEqual(vector[4], Pkcs8(priv), label + " pkcs8 at 5");
                }

                AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(Hex.Decode(vector[1]));
                Assert.AreEqual(vector[1], Hex.ToHexString(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub).GetEncoded()), label + " spki again");
                for (int i = 2; i != 5; i++)
                {
                    // read twice from one PrivateKeyInfo: reading it leaves it as it was
                    PrivateKeyInfo info = PrivateKeyInfo.GetInstance(Hex.Decode(vector[i]));
                    PrivateKeyFactory.CreateKey(info);
                    AsymmetricKeyParameter decoded = PrivateKeyFactory.CreateKey(info);
                    Assert.AreEqual(vector[i], Pkcs8(decoded), label + " pkcs8 again " + i);
                    Assert.AreEqual(vector[i], Hex.ToHexString(info.GetEncoded()), label + " info untouched " + i);
                }
            }
        }

        /// <summary>
        /// A key read from bc-java's PKCS#8 carries the index it was written at, and the next signature it makes is
        /// bc-java's next signature, at that index: a stored key never rewinds through the key factories.
        /// </summary>
        [Test]
        public void JavaVectors_DecodedKeyContinuesAtItsIndex()
        {
            foreach (string[] vector in JavaVectors)
            {
                string label = vector[0];
                AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(Hex.Decode(vector[1]));

                AsymmetricKeyParameter at3 = PrivateKeyFactory.CreateKey(Hex.Decode(vector[2]));
                Assert.AreEqual(3L, IndexOf(at3), label + " index at 3");
                Assert.AreEqual(UsagesOf(pub) - 3, UsagesRemaining(at3), label + " usages at 3");

                AsymmetricKeyParameter shard = PrivateKeyFactory.CreateKey(Hex.Decode(vector[3]));
                Assert.AreEqual(3L, IndexOf(shard), label + " shard index");
                Assert.AreEqual(2L, UsagesRemaining(shard), label + " shard usages");

                AsymmetricKeyParameter at5 = PrivateKeyFactory.CreateKey(Hex.Decode(vector[4]));
                Assert.AreEqual(5L, IndexOf(at5), label + " index at 5");

                ISigner signer = NewSigner(at5);
                signer.Init(true, at5);
                signer.BlockUpdate(Message, 0, Message.Length);
                byte[] sig = signer.GenerateSignature();

                Assert.AreEqual(vector[5], Sha256(sig), label + " signature at 5");
                Assert.AreEqual(6L, IndexOf(at5), label + " index after signing");

                ISigner verifier = NewSigner(pub);
                verifier.Init(false, pub);
                verifier.BlockUpdate(Message, 0, Message.Length);
                Assert.IsTrue(verifier.VerifySignature(sig), label + " signature at 5 did not verify");

                // and the key written out again after signing carries the index it moved on to
                AsymmetricKeyParameter at6 = PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(at5).GetEncoded());
                Assert.AreEqual(6L, IndexOf(at6), label + " index after round trip");
            }
        }

        /// <summary>
        /// bc-java's legacy XMSS^MT PKCS#8 at index 3, with the index INTEGER rewritten to 0 and nothing else
        /// touched. The layer zero state there sits on the last leaf of the first subtree, the position a state is
        /// carried over from when the index moves into the next one; read as a carry-over into index 0, the key would
        /// sign indices 0 to 2 again, with signatures that verify. It is refused on the way in.
        /// </summary>
        [Test]
        public void LegacyXmssMTKeyWithIndexMovedBackRefused()
        {
            string[] vector = Array.Find(JavaVectors, v => v[0] == "XMSSMT h4d2 SHA-256");
            byte[] pkcs8 = Hex.Decode(vector[2]);

            // SEQUENCE { INTEGER index, ... } of the XMSS^MT private key body
            Assert.AreEqual("8b020103", Hex.ToHexString(pkcs8, 58, 4));
            pkcs8[61] = 0;

            ArgumentException e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(pkcs8));
            StringAssert.Contains("BDS state has wrong index for layer 0", e.Message);
        }

        /// <summary>
        /// A destroyed key is not written out in either form: the legacy form reads its seeds through the checked
        /// getters, the RFC 9802 form through <see cref="XmssPrivateKeyParameters.GetEncoded"/>.
        /// </summary>
        [Test]
        public void DestroyedKey_CreatePrivateKeyInfo_Throws()
        {
            foreach (string label in new string[]{ "XMSS h4 SHA-256", "XMSSMT h4d2 SHA-256", "XMSSMT-SHA2_20/4_256" })
            {
                AsymmetricKeyParameter priv = GenerateCounting(label).Private;
                if (priv is XmssPrivateKeyParameters xmss)
                {
                    xmss.Destroy();
                }
                else
                {
                    ((XmssMTPrivateKeyParameters)priv).Destroy();
                }

                InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                    () => PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv), label);
                Assert.AreEqual("key destroyed", e.Message, label);
            }
        }

        /// <summary>
        /// Attributes handed to <see cref="PrivateKeyInfoFactory.CreatePrivateKeyInfo(AsymmetricKeyParameter,
        /// Org.BouncyCastle.Asn1.Asn1Set)"/> are carried in the PrivateKeyInfo, in the legacy form and the RFC 9802
        /// form, and the key still reads back from it at its index.
        /// </summary>
        [Test]
        public void CreatePrivateKeyInfo_WithAttributes()
        {
            Asn1Set attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                new DerSet(new DerBmpString("xmss key"))));

            foreach (string label in new string[]{ "XMSS h4 SHA-256", "XMSSMT h4d2 SHA-256", "XMSSMT-SHA2_20/4_256" })
            {
                AsymmetricKeyParameter priv = SignThrice(GenerateCounting(label).Private);

                PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv, attributes);
                Assert.IsNotNull(info.Attributes, label);
                Assert.AreEqual(attributes.GetEncoded(), info.Attributes.GetEncoded(), label + " attributes");

                PrivateKeyInfo reread = PrivateKeyInfo.GetInstance(info.GetEncoded());
                Assert.AreEqual(attributes.GetEncoded(), reread.Attributes.GetEncoded(), label + " attributes reread");

                AsymmetricKeyParameter decoded = PrivateKeyFactory.CreateKey(reread);
                Assert.AreEqual(3L, IndexOf(decoded), label + " index");
                Assert.AreEqual(Pkcs8(priv), Pkcs8(decoded), label + " key");
            }
        }

        private void CheckXmss(int paramSetOid, int expectedN)
        {
            XmssParameters parameters = XmssParameters.LookupByOid(paramSetOid);
            Assert.IsNotNull(parameters, "no XMSS parameter set for OID " + paramSetOid);
            Assert.AreEqual(expectedN, parameters.TreeDigestSize);

            XmssKeyPairGenerator gen = new XmssKeyPairGenerator();
            gen.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;

            PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv);

            // private key shares the RFC 9802 OID the public key uses (no OID divergence)
            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmss_hashsig, pkInfo.PrivateKeyAlgorithm.Algorithm);
            SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public);
            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmss_hashsig, spkInfo.Algorithm.Algorithm);

            // private key round-trips losslessly to the same parameter set
            XmssPrivateKeyParameters recovered = (XmssPrivateKeyParameters)PrivateKeyFactory.CreateKey(pkInfo);
            Assert.AreEqual(paramSetOid, recovered.Parameters.ParameterSetOid);
            Assert.AreEqual(expectedN, recovered.Parameters.TreeDigestSize);
            Assert.AreEqual(priv.GetEncoded(), recovered.GetEncoded());
        }

        private void CheckXmssMt(int paramSetOid, int expectedN)
        {
            XmssMTParameters parameters = XmssMTParameters.LookupByOid(paramSetOid);
            Assert.IsNotNull(parameters, "no XMSS^MT parameter set for OID " + paramSetOid);
            Assert.AreEqual(expectedN, parameters.TreeDigestSize);

            XmssMTKeyPairGenerator gen = new XmssMTKeyPairGenerator();
            gen.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;

            PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv);

            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmssmt_hashsig, pkInfo.PrivateKeyAlgorithm.Algorithm);
            SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public);
            Assert.AreEqual(IanaObjectIdentifiers.id_alg_xmssmt_hashsig, spkInfo.Algorithm.Algorithm);

            XmssMTPrivateKeyParameters recovered = (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(pkInfo);
            Assert.AreEqual(paramSetOid, recovered.Parameters.ParameterSetOid);
            Assert.AreEqual(expectedN, recovered.Parameters.TreeDigestSize);
            Assert.AreEqual(priv.GetEncoded(), recovered.GetEncoded());
        }

        /// <summary>The vector's key pair, from the bytes 0, 1, 2, ..., or null for the height 10 tree.</summary>
        private static AsymmetricCipherKeyPair GenerateCounting(string label)
        {
            switch (label)
            {
            case "XMSS h4 SHA-256":
                return GenerateXmss(new XmssParameters(4, NistObjectIdentifiers.IdSha256));
            case "XMSSMT h4d2 SHA-256":
                return GenerateXmssMT(new XmssMTParameters(4, 2, NistObjectIdentifiers.IdSha256));
            case "XMSSMT-SHA2_20/4_256":
                return GenerateXmssMT(XmssMTParameters.LookupByOid(2));
            default:
                return null;
            }
        }

        private static AsymmetricCipherKeyPair GenerateXmss(XmssParameters parameters)
        {
            XmssKeyPairGenerator gen = new XmssKeyPairGenerator();
            gen.Init(new XmssKeyGenerationParameters(CountingRandom(parameters.TreeDigestSize), parameters));
            return gen.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateXmssMT(XmssMTParameters parameters)
        {
            XmssMTKeyPairGenerator gen = new XmssMTKeyPairGenerator();
            gen.Init(new XmssMTKeyGenerationParameters(CountingRandom(parameters.TreeDigestSize), parameters));
            return gen.GenerateKeyPair();
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

        private static AsymmetricKeyParameter SignThrice(AsymmetricKeyParameter priv)
        {
            if (priv is XmssPrivateKeyParameters)
            {
                XmssSigner signer = new XmssSigner();
                signer.Init(true, priv);
                for (int i = 0; i != 3; i++)
                {
                    XmssHarnessTests.Sign(signer, Message);
                }
                return signer.GetUpdatedPrivateKey();
            }
            else
            {
                XmssMTSigner signer = new XmssMTSigner();
                signer.Init(true, priv);
                for (int i = 0; i != 3; i++)
                {
                    XmssHarnessTests.Sign(signer, Message);
                }
                return signer.GetUpdatedPrivateKey();
            }
        }

        private static ISigner NewSigner(AsymmetricKeyParameter key) =>
            (key is XmssPrivateKeyParameters || key is XmssPublicKeyParameters)
                ? (ISigner)new XmssSigner() : new XmssMTSigner();

        private static long IndexOf(AsymmetricKeyParameter key) =>
            (key is XmssPrivateKeyParameters xmss) ? xmss.Index : ((XmssMTPrivateKeyParameters)key).Index;

        private static long UsagesRemaining(AsymmetricKeyParameter key) => (key is XmssPrivateKeyParameters xmss)
            ? xmss.GetUsagesRemaining() : ((XmssMTPrivateKeyParameters)key).GetUsagesRemaining();

        private static long UsagesOf(AsymmetricKeyParameter pub) => (pub is XmssPublicKeyParameters xmss)
            ? 1L << xmss.Parameters.Height : 1L << ((XmssMTPublicKeyParameters)pub).Parameters.Height;

        private static string Pkcs8(AsymmetricKeyParameter priv) =>
            Hex.ToHexString(PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv).GetEncoded());

        private static string Sha256(byte[] data)
        {
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            return Hex.ToHexString(output);
        }

        /// <summary>A vector too long to keep inline, as the hex string the table holds.</summary>
        private static string LoadVector(string name) => Hex.ToHexString(
            XmssTestData.LoadHex("XmssPrivateKeyEncodingTests.JavaVectors_XmssMTSha2_20_4_256." + name + ".hex"));

        internal static readonly string[][] JavaVectors =
        {
            new string[]
            {
                "XMSS h4 SHA-256",
                "306f3021060a2b0601040181b01a02023013020100020104300b0609608648016503040201034a003047020100042040"
                + "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f042079f9d5e9bba4628aee015408559590"
                + "ebdfb79a142980203cc0a30610054177de",
                "308202a70201003021060a2b0601040181b01a02023013020100020104300b06096086480165030402010482027d3082"
                + "027902010030818b0201030420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f042020"
                + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b4c4d4e"
                + "4f505152535455565758595a5b5c5d5e5f042079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3061005"
                + "4177dea18201e4048201e0424453000000000100000004000000020000000f000000030001000000040000002079f9d5"
                + "e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de000000040000000000000020f47cf5e9da530e"
                + "2e7f8f416c56501f10da566960db66f6bbed631df531969a6100000001000000206b070e08b3e8ab0b3fba824a35eaef"
                + "f86ec5c0818ee034be8c2ce282be33ed800000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82d"
                + "f125dd902c902669e8000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be218579e94bbe7c0bf"
                + "cf000000010000000200000001000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0097f96"
                + "1323d5254d00000000000000020000000000000000000000050101010000000000000020918e2cc1ff7b84ad19cdfb9a"
                + "0c64598f54705c24e34d837410c0d078c28db5ba00000001000000010000000000010100000001000000206cb8aa9165"
                + "f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e400000001000000010000000100000020e27018bee1"
                + "e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f582fcc9ff6bbd9d69b2cb986a1fdbbbc5f1392e276b"
                + "14ad9da37654f6bdda8d30",
                "308202aa0201003021060a2b0601040181b01a02023013020100020104300b0609608648016503040201048202803082"
                + "027c02010130818e0201030420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f042020"
                + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b4c4d4e"
                + "4f505152535455565758595a5b5c5d5e5f042079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3061005"
                + "4177de800104a18201e4048201e042445300000000010000000400000002000000040000000300010000000400000020"
                + "79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de000000040000000000000020f47cf5e9"
                + "da530e2e7f8f416c56501f10da566960db66f6bbed631df531969a6100000001000000206b070e08b3e8ab0b3fba824a"
                + "35eaeff86ec5c0818ee034be8c2ce282be33ed800000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2"
                + "d1c82df125dd902c902669e8000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be218579e94bb"
                + "e7c0bfcf000000010000000200000001000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0"
                + "097f961323d5254d00000000000000020000000000000000000000050101010000000000000020918e2cc1ff7b84ad19"
                + "cdfb9a0c64598f54705c24e34d837410c0d078c28db5ba00000001000000010000000000010100000001000000206cb8"
                + "aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e400000001000000010000000100000020e270"
                + "18bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5fc8d8fc41f6b970c2ce7f671e26ed4de7af7"
                + "580b56588aaaa1f5e15a07aff4fc",
                "308202d30201003021060a2b0601040181b01a02023013020100020104300b0609608648016503040201048202a93082"
                + "02a502010030818b0201050420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f042020"
                + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b4c4d4e"
                + "4f505152535455565758595a5b5c5d5e5f042079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3061005"
                + "4177dea18202100482020c424453000000000100000004000000020000000f000000050001000000040000002079f9d5"
                + "e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de000000040000000000000020b3495c6e53ac46"
                + "6f4176d51d4ba4c5a8102d6138a24272af23c7a2bba83dc95700000001000000206cb8aa9165f5205de7535ddd09a1b8"
                + "4e8d57d78c837e3d3589956d87c8efa4e40000000200000020459a423afd247679ab8102df23c4e781f3a8df70a3d544"
                + "03bffbed62bce8d373000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be218579e94bbe7c0bf"
                + "cf000000010000000200000001000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0097f96"
                + "1323d5254d0000000000000002000000000000000000000007010101000000000000002037bb88e11581df5ff649ee5d"
                + "7491f9769782800ea3f2f983c7d73bad0ee2d2d400000001000000000000000b0100010000000000000020aa66295ea5"
                + "e17ff7aadede4df773596638caa2177a8705e4855a5096d54a369d00000002000000000000000000000020918e2cc1ff"
                + "7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28db5ba000000020000000200000020d1f3876cc98c46c492"
                + "85a77fc111c928b340d7d2d1c82df125dd902c902669e8b264d50fa991d34b31a2b09c657f6dda27fcba9f2c3444ecae"
                + "cbcb19971d26ae",
                "0aa24d9cb2e9fa4093ed4c0378b72339b4b04215c3fd539a766e0ad8af902e5c",
            },
            new string[]
            {
                "XMSS-SHA2_10_256",
                "3053300a06082b060105050706220345000000000185055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bf"
                + "bde1ba9cc4404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                "308204b9020100300a06082b06010505070622048204a6048204a20000000100000003000102030405060708090a0b0c"
                + "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"
                + "3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f85055d10d75c7d9f50d5d90dd4"
                + "3827a90fbcf397b76d3877ba85bfbde1ba9cc442445300000000010000000a00000002000003ff000000030001000000"
                + "0a0000002085055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc40000000a00000000000000"
                + "20f47cf5e9da530e2e7f8f416c56501f10da566960db66f6bbed631df531969a6100000001000000206b070e08b3e8ab"
                + "0b3fba824a35eaeff86ec5c0818ee034be8c2ce282be33ed800000000200000020d1f3876cc98c46c49285a77fc111c9"
                + "28b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be2"
                + "18579e94bbe7c0bfcf00000004000000207fa6b5eb231fdba25172edd2c7ca5b62ab47896d6db77d61e3245687b3447d"
                + "540000000500000020589185e48d2d09b9d00eef5b3120c61c4ae5d80b2db67cdcfeef163942c5fdb400000006000000"
                + "20ec2abf80b41083e3c66db3a9569b466a66dd21f9ff225bd77c43b7e6e9ece4df0000000700000020c85b31510868d3"
                + "f7c03dc4024d164ca74386edb59708b2d1d6bc418bde4404580000000800000020560566ee6f35497c224298b16740c4"
                + "158d5d369e80d3aaa6e75969207cbed00500000009000000209d8828eb13493fa98d516a1b87b9528b31a63975268760"
                + "a59543cb4bae3403bc00000001000000080000000100000008000000205512ffdc18cc64a201e3d5a189bbe38f2793d9"
                + "a835b73421ab3bcd00d7aa734900000000000000080000000000000000000000050101010000000000000020918e2cc1"
                + "ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28db5ba0000000100000001000000000001010000000100"
                + "0000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e400000002000000020000000000"
                + "0101000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000030000"
                + "0003000000000001010000000300000020ff7c4238f040c81306f3fe7e84fe7201bab69d5e1f721a7dd86d858feae300"
                + "a9000000040000000400000000000101000000040000002055aeb24e79e15b2fd7e4d14fc6ee4138ce908b74a573825e"
                + "7c20c14ed8671f67000000050000000500000000000101000000050000002093483dacc20a2707a92d47780643bd1c90"
                + "8925e4f7104ea1f6195f0d1a3a465f00000006000000060000000000010100000006000000201b20cd7e03af01c8c3c0"
                + "2541b0a987021031e3c5104c5077fd3bc8f4a097462d0000000700000007000000000001010000000700000020f0be26"
                + "c249b7362ec7b7445c2740c32610f97bff061f424a7e55168fe8ce5b5000000001000000010000000100000020e27018"
                + "bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f52ca2b31993cefe114dd9e18b6e13183fa14fa1"
                + "851bf9d4c94bdc355115b9a301",
                "308204b9020100300a06082b06010505070622048204a6048204a20000000100000003000102030405060708090a0b0c"
                + "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"
                + "3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f85055d10d75c7d9f50d5d90dd4"
                + "3827a90fbcf397b76d3877ba85bfbde1ba9cc442445300000000010000000a0000000200000004000000030001000000"
                + "0a0000002085055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc40000000a00000000000000"
                + "20f47cf5e9da530e2e7f8f416c56501f10da566960db66f6bbed631df531969a6100000001000000206b070e08b3e8ab"
                + "0b3fba824a35eaeff86ec5c0818ee034be8c2ce282be33ed800000000200000020d1f3876cc98c46c49285a77fc111c9"
                + "28b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be2"
                + "18579e94bbe7c0bfcf00000004000000207fa6b5eb231fdba25172edd2c7ca5b62ab47896d6db77d61e3245687b3447d"
                + "540000000500000020589185e48d2d09b9d00eef5b3120c61c4ae5d80b2db67cdcfeef163942c5fdb400000006000000"
                + "20ec2abf80b41083e3c66db3a9569b466a66dd21f9ff225bd77c43b7e6e9ece4df0000000700000020c85b31510868d3"
                + "f7c03dc4024d164ca74386edb59708b2d1d6bc418bde4404580000000800000020560566ee6f35497c224298b16740c4"
                + "158d5d369e80d3aaa6e75969207cbed00500000009000000209d8828eb13493fa98d516a1b87b9528b31a63975268760"
                + "a59543cb4bae3403bc00000001000000080000000100000008000000205512ffdc18cc64a201e3d5a189bbe38f2793d9"
                + "a835b73421ab3bcd00d7aa734900000000000000080000000000000000000000050101010000000000000020918e2cc1"
                + "ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28db5ba0000000100000001000000000001010000000100"
                + "0000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e400000002000000020000000000"
                + "0101000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000030000"
                + "0003000000000001010000000300000020ff7c4238f040c81306f3fe7e84fe7201bab69d5e1f721a7dd86d858feae300"
                + "a9000000040000000400000000000101000000040000002055aeb24e79e15b2fd7e4d14fc6ee4138ce908b74a573825e"
                + "7c20c14ed8671f67000000050000000500000000000101000000050000002093483dacc20a2707a92d47780643bd1c90"
                + "8925e4f7104ea1f6195f0d1a3a465f00000006000000060000000000010100000006000000201b20cd7e03af01c8c3c0"
                + "2541b0a987021031e3c5104c5077fd3bc8f4a097462d0000000700000007000000000001010000000700000020f0be26"
                + "c249b7362ec7b7445c2740c32610f97bff061f424a7e55168fe8ce5b5000000001000000010000000100000020e27018"
                + "bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f573cc212e9e1c4ccd88a0eb0b62b921298f3207"
                + "fa1e641a1925067225670a9273",
                "308204e5020100300a06082b06010505070622048204d2048204ce0000000100000005000102030405060708090a0b0c"
                + "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"
                + "3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f85055d10d75c7d9f50d5d90dd4"
                + "3827a90fbcf397b76d3877ba85bfbde1ba9cc442445300000000010000000a00000002000003ff000000050001000000"
                + "0a0000002085055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc40000000a00000000000000"
                + "20b3495c6e53ac466f4176d51d4ba4c5a8102d6138a24272af23c7a2bba83dc95700000001000000206cb8aa9165f520"
                + "5de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e40000000200000020459a423afd247679ab8102df23c4e7"
                + "81f3a8df70a3d54403bffbed62bce8d373000000030000002068538e5a1e958ac7475ad526a9a311260e805687429be2"
                + "18579e94bbe7c0bfcf00000004000000207fa6b5eb231fdba25172edd2c7ca5b62ab47896d6db77d61e3245687b3447d"
                + "540000000500000020589185e48d2d09b9d00eef5b3120c61c4ae5d80b2db67cdcfeef163942c5fdb400000006000000"
                + "20ec2abf80b41083e3c66db3a9569b466a66dd21f9ff225bd77c43b7e6e9ece4df0000000700000020c85b31510868d3"
                + "f7c03dc4024d164ca74386edb59708b2d1d6bc418bde4404580000000800000020560566ee6f35497c224298b16740c4"
                + "158d5d369e80d3aaa6e75969207cbed00500000009000000209d8828eb13493fa98d516a1b87b9528b31a63975268760"
                + "a59543cb4bae3403bc00000001000000080000000100000008000000205512ffdc18cc64a201e3d5a189bbe38f2793d9"
                + "a835b73421ab3bcd00d7aa73490000000000000008000000000000000000000007010101000000000000002037bb88e1"
                + "1581df5ff649ee5d7491f9769782800ea3f2f983c7d73bad0ee2d2d400000001000000000000000b0101010000000100"
                + "0000203b8b20a984eb0186ee8aa31778ed302e50dca4a4260d1d031d13846f08a680a100000002000000020000000000"
                + "0101000000020000002097988034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000030000"
                + "0003000000000001010000000300000020ff7c4238f040c81306f3fe7e84fe7201bab69d5e1f721a7dd86d858feae300"
                + "a9000000040000000400000000000101000000040000002055aeb24e79e15b2fd7e4d14fc6ee4138ce908b74a573825e"
                + "7c20c14ed8671f67000000050000000500000000000101000000050000002093483dacc20a2707a92d47780643bd1c90"
                + "8925e4f7104ea1f6195f0d1a3a465f00000006000000060000000000010100000006000000201b20cd7e03af01c8c3c0"
                + "2541b0a987021031e3c5104c5077fd3bc8f4a097462d0000000700000007000000000001010000000700000020f0be26"
                + "c249b7362ec7b7445c2740c32610f97bff061f424a7e55168fe8ce5b5000000002000000000000000000000020918e2c"
                + "c1ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28db5ba000000020000000200000020d1f3876cc98c46"
                + "c49285a77fc111c928b340d7d2d1c82df125dd902c902669e897628cfd7b5dfdd8a9c58d06bbf2599d476c1ba40f28d9"
                + "3ecded6d2da222df3d",
                "f425c5c3e76fb2838ee5fc4e6f62300851cfd5b36e0c8c964969c1ed3fe9a865",
            },
            new string[]
            {
                "XMSSMT h4d2 SHA-256",
                "30723024060a2b0601040181b01a02033016020100020104020102300b0609608648016503040201034a003047020100"
                + "0420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0420cf4057feb3275804643c06ac"
                + "dfb79de6a4eacb58b0f5791c7b9d204237621799",
                "3082027a0201003024060a2b0601040181b01a02033016020100020104020102300b0609608648016503040201048202"
                + "4d3082024902010030818b0201030420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b"
                + "4c4d4e4f505152535455565758595a5b5c5d5e5f0420cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d"
                + "204237621799a18201b4048201b042444d0000000001000000000000000f000000020000000000000002000000020000"
                + "00030000000300010000000200000020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bce8d373"
                + "000000020000000000000020f47cf5e9da530e2e7f8f416c56501f10da566960db66f6bbed631df531969a6100000001"
                + "000000206b070e08b3e8ab0b3fba824a35eaeff86ec5c0818ee034be8c2ce282be33ed80000000010000000000000000"
                + "000000000000000000000000000000010000000200000002000000030000000000010000000200000020cf4057feb327"
                + "5804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179900000002000000000000002033f925bca69b9e81c615"
                + "3d57b8346b23cceca97a2b851b81f598b06e6b1144140000000100000020403421e4177823bbbc1b3c7056f9a5949f7d"
                + "5721fecad65c64ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e637d92ff2794e16"
                + "d2c827dffe463f3f2f328b903f5c0375f64c000000000000000000000000dc8692269452ab11be7e3b49f2cafc89a4b9"
                + "81ce47ee8a356cbd4bb82aadae5f",
                "3082027d0201003024060a2b0601040181b01a02033016020100020104020102300b0609608648016503040201048202"
                + "503082024c02010130818e0201030420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b"
                + "4c4d4e4f505152535455565758595a5b5c5d5e5f0420cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d"
                + "204237621799800104a18201b4048201b042444d00000000010000000000000004000000020000000000000002000000"
                + "02000000030000000300010000000200000020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bc"
                + "e8d373000000020000000000000020f47cf5e9da530e2e7f8f416c56501f10da566960db66f6bbed631df531969a6100"
                + "000001000000206b070e08b3e8ab0b3fba824a35eaeff86ec5c0818ee034be8c2ce282be33ed80000000010000000000"
                + "000000000000000000000000000000000000010000000200000002000000030000000000010000000200000020cf4057"
                + "feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d20423762179900000002000000000000002033f925bca69b9e"
                + "81c6153d57b8346b23cceca97a2b851b81f598b06e6b1144140000000100000020403421e4177823bbbc1b3c7056f9a5"
                + "949f7d5721fecad65c64ea4f7b64fb73690000000100000000000000010000000000000020e12c101fd563e637d92ff2"
                + "794e16d2c827dffe463f3f2f328b903f5c0375f64c000000000000000000000000e9636fe304c288f5420935a7796108"
                + "3fc47892df5ce5114a6db05b5dde4fbc28",
                "308202fa0201003024060a2b0601040181b01a02033016020100020104020102300b0609608648016503040201048202"
                + "cd308202c902010030818b0201050420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "0420202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0420404142434445464748494a4b"
                + "4c4d4e4f505152535455565758595a5b5c5d5e5f0420cf4057feb3275804643c06acdfb79de6a4eacb58b0f5791c7b9d"
                + "204237621799a18202340482023042444d0000000001000000000000000f000000020000000000000002000000020000"
                + "00030000000100010000000200000020d0a45fea03c7dd7d23ef70220c2fef542562b54fc3278146dca6e28175c68fd9"
                + "000000020000000000000020fa43b24d6ff309db5f3d4f1c3e7cd5898e92e8e9cd837cfb35631eac6f44da9300000001"
                + "00000020945e8dae08dfb431ed428173c473a77ceb1f54a6182d78b9409abd4c0d083064000000010000000000000001"
                + "0000000000000020b09f83bc26c36611bfbb9f3959bc2cee86c1d5501827e1d6703c8e97769568c70000000000000000"
                + "000000010000000000000000000000202e8c1b719052b12a9f842d493163ef0995789c7efe005e7ef7ae81dc3f74ba42"
                + "000000010000000200000002000000030000000100010000000200000020cf4057feb3275804643c06acdfb79de6a4ea"
                + "cb58b0f5791c7b9d204237621799000000020000000000000020fdc539c5013b0318fb567893ac83e6ca40d39ebb477d"
                + "2a2a16ef50935b6b32380000000100000020403421e4177823bbbc1b3c7056f9a5949f7d5721fecad65c64ea4f7b64fb"
                + "73690000000100000000000000010000000000000020e12c101fd563e637d92ff2794e16d2c827dffe463f3f2f328b90"
                + "3f5c0375f64c00000000000000000000000100000000000000000000002033f925bca69b9e81c6153d57b8346b23ccec"
                + "a97a2b851b81f598b06e6b114414c76c6f44c896647f8087d2ce6b9156d155ef693692c27c9146630f7a512ae1f0",
                "01ef2d843cb2ac9b1b7ea634966f7f87835292ed38a38455bb6ae849afe5d5d4",
            },
            new string[]
            {
                "XMSSMT-SHA2_20/4_256",
                "3053300a06082b0601050507062303450000000002e9faa5638cf84a5f2c66b9a8041f90ff2950b44aa01c381b06d89c"
                + "fb0e8ce4de404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                LoadVector("Pkcs8At3"),
                LoadVector("ShardAt3"),
                LoadVector("Pkcs8At5"),
                "9027da887f22d202667956ac4802d20f71aecdb781e6c61c57d34bfa662b501d",
            },
        };
    }
}
