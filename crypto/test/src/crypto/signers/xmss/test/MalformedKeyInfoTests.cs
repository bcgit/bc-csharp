using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A key that will not decode is reported by the key factories as an <see cref="ArgumentException"/>, wherever in
    /// the decode it goes wrong: an algorithm identifier carrying the wrong parameters, or none at all, a key body of
    /// the wrong shape, or an integer field too wide for what it is read into.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Java's factories are declared <c>throws IOException</c> and report these as IOException; here the same
    /// messages come out as ArgumentException, the exception the factories report every other malformed key with.
    /// </para>
    /// <para>
    /// The cause is kept as well: the factory's own message says which key it was, and InnerException says what was
    /// wrong with it.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class MalformedKeyInfoTests
    {
        private static readonly AlgorithmIdentifier TreeDigest =
            new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);

        private static XmssPrivateKey PrivateKeyBody() =>
            new XmssPrivateKey(0, new byte[32], new byte[32], new byte[32], new byte[32], null);

        private static void CheckPrefix(string prefix, TestDelegate code, bool causeKept = true)
        {
            ArgumentException e = Assert.Throws<ArgumentException>(code);
            Assert.IsTrue(e.Message.StartsWith(prefix), e.Message);
            if (causeKept)
            {
                Assert.IsNotNull(e.InnerException, "the cause of a malformed key is kept");
            }
        }

        /// <summary>An XMSS OID with no algorithm parameters at all; the XMSS^MT twin is the same.</summary>
        [Test]
        public void TestPrivateKeyWithNoParameters()
        {
            ArgumentException e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(
                new PrivateKeyInfo(new AlgorithmIdentifier(PqcObjectIdentifiers.xmss), PrivateKeyBody())));
            Assert.AreEqual("no parameters found in XMSS private key", e.Message);

            e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(
                new PrivateKeyInfo(new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt), PrivateKeyBody())));
            Assert.AreEqual("no parameters found in XMSS^MT private key", e.Message);
        }

        /// <summary>An XMSS OID whose parameters are present but are not an XmssKeyParams.</summary>
        [Test]
        public void TestKeyWithParametersOfTheWrongShape()
        {
            AlgorithmIdentifier xmss = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss, new DerInteger(1));
            AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt, new DerInteger(1));

            CheckPrefix("malformed XMSS public key: ", () => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(xmss, new XmssPublicKey(new byte[32], new byte[32]))));
            CheckPrefix("malformed XMSS^MT public key: ", () => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(xmssMt, new XmssPublicKey(new byte[32], new byte[32]))));
            CheckPrefix("malformed XMSS private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmss, PrivateKeyBody())));
            CheckPrefix("malformed XMSS^MT private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssMt, PrivateKeyBody())));
        }

        /// <summary>Well-formed parameters, but a key body that is not the structure they call for.</summary>
        [Test]
        public void TestKeyWithBodyOfTheWrongShape()
        {
            AlgorithmIdentifier xmss = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss,
                new XmssKeyParams(4, TreeDigest));
            AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                new XmssMTKeyParams(4, 2, TreeDigest));

            CheckPrefix("malformed XMSS public key: ",
                () => PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(xmss, new DerInteger(1))));
            CheckPrefix("malformed XMSS^MT public key: ",
                () => PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(xmssMt, new DerInteger(1))));
            CheckPrefix("malformed XMSS private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmss, new DerInteger(1))));
            CheckPrefix("malformed XMSS^MT private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssMt, new DerInteger(1))));
        }

        /// <summary>
        /// The RFC 9802 form, whose octets are a parameter-set OID and a raw key, with a body that is not an OCTET
        /// STRING, and the length and OID checks below it, which report without a cause.
        /// </summary>
        [Test]
        public void TestRfc9802KeyWithBodyOfTheWrongShape()
        {
            AlgorithmIdentifier xmss = new AlgorithmIdentifier(IanaObjectIdentifiers.id_alg_xmss_hashsig);
            AlgorithmIdentifier xmssMt = new AlgorithmIdentifier(IanaObjectIdentifiers.id_alg_xmssmt_hashsig);

            CheckPrefix("malformed XMSS private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmss, new DerInteger(1))));
            CheckPrefix("malformed XMSS^MT private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssMt, new DerInteger(1))));

            ArgumentException e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(
                new PrivateKeyInfo(xmssMt, new DerOctetString(new byte[3]))));
            Assert.AreEqual("XMSS^MT private key data too short", e.Message);

            e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(
                new PrivateKeyInfo(xmssMt, new DerOctetString(new byte[]{ 0x7f, 0xff, 0xff, 0xff, 0x00 }))));
            Assert.IsTrue(e.Message.StartsWith("unknown XMSS^MT private key OID: "), e.Message);
        }

        /// <summary>
        /// A height or layer count too large for the int it is read into: <see cref="DerInteger.IntValueExact"/>
        /// reports it as an <see cref="ArithmeticException"/>, which the factories report as a malformed key.
        /// </summary>
        [Test]
        public void TestKeyWithAnOversizedIntegerField()
        {
            DerInteger wide = new DerInteger(BigInteger.One.ShiftLeft(40));

            AlgorithmIdentifier xmssWideHeight = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss,
                new DerSequence(DerInteger.Zero, wide, TreeDigest));
            AlgorithmIdentifier xmssMtWideHeight = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                new DerSequence(DerInteger.Zero, wide, new DerInteger(2), TreeDigest));
            AlgorithmIdentifier xmssMtWideLayers = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                new DerSequence(DerInteger.Zero, new DerInteger(4), wide, TreeDigest));

            CheckPrefix("malformed XMSS public key: ", () => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(xmssWideHeight, new XmssPublicKey(new byte[32], new byte[32]))));
            CheckPrefix("malformed XMSS private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssWideHeight, PrivateKeyBody())));
            CheckPrefix("malformed XMSS^MT public key: ", () => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(xmssMtWideHeight, new XmssPublicKey(new byte[32], new byte[32]))));
            CheckPrefix("malformed XMSS^MT private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssMtWideHeight, PrivateKeyBody())));
            CheckPrefix("malformed XMSS^MT public key: ", () => PublicKeyFactory.CreateKey(
                new SubjectPublicKeyInfo(xmssMtWideLayers, new XmssPublicKey(new byte[32], new byte[32]))));
            CheckPrefix("malformed XMSS^MT private key: ",
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(xmssMtWideLayers, PrivateKeyBody())));
        }

        /// <summary>
        /// Every proper prefix of an XMSS / XMSS^MT PrivateKeyInfo and SubjectPublicKeyInfo encoding, in each of the
        /// forms the factories write, is refused with an ArgumentException-derived exception or an
        /// InvalidOperationException, never an index or null reference error: both the whole encoding cut short, and
        /// the key octets inside a well-formed info cut short or carrying a byte too many.
        /// </summary>
        /// <remarks>
        /// The encodings are the bc-java ones <see cref="XmssPrivateKeyEncodingTests"/> checks against: the legacy
        /// form (height 4, and height 4 over 2 layers) and the RFC 9802 form (XMSS-SHA2_10_256 and
        /// XMSSMT-SHA2_20/4_256), each at index 3, and a shard carrying a maximum index.
        /// </remarks>
        [Test]
        public void AllDecoders_Truncations_AreRefused()
        {
            foreach (string[] vector in XmssPrivateKeyEncodingTests.JavaVectors)
            {
                string label = vector[0];

                foreach (int which in new int[]{ 2, 3 })
                {
                    byte[] pkcs8 = Hex.Decode(vector[which]);
                    PrivateKeyInfo info = PrivateKeyInfo.GetInstance(pkcs8);
                    byte[] octets = info.PrivateKey.GetOctets();

                    for (int len = 0; len != pkcs8.Length; len++)
                    {
                        byte[] prefix = Arrays.CopyOfRange(pkcs8, 0, len);
                        AssertRefused(() => PrivateKeyFactory.CreateKey(prefix), label + " PKCS#8 prefix " + len);
                    }
                    for (int len = 0; len != octets.Length; len++)
                    {
                        PrivateKeyInfo cut = PrivateKeyInfo.Create(info.PrivateKeyAlgorithm,
                            new DerOctetString(Arrays.CopyOfRange(octets, 0, len)), null, null);
                        AssertRefused(() => PrivateKeyFactory.CreateKey(cut), label + " private key octets " + len);
                    }
                    PrivateKeyInfo longer = PrivateKeyInfo.Create(info.PrivateKeyAlgorithm,
                        new DerOctetString(Arrays.Append(octets, 0x00)), null, null);
                    AssertRefused(() => PrivateKeyFactory.CreateKey(longer), label + " private key octets + 1");
                }

                byte[] spki = Hex.Decode(vector[1]);
                SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(spki);
                byte[] keyData = pubInfo.PublicKey.GetOctets();

                for (int len = 0; len != spki.Length; len++)
                {
                    byte[] prefix = Arrays.CopyOfRange(spki, 0, len);
                    AssertRefused(() => PublicKeyFactory.CreateKey(prefix), label + " SPKI prefix " + len);
                }
                for (int len = 0; len != keyData.Length; len++)
                {
                    SubjectPublicKeyInfo cut = new SubjectPublicKeyInfo(pubInfo.Algorithm,
                        Arrays.CopyOfRange(keyData, 0, len));
                    AssertRefused(() => PublicKeyFactory.CreateKey(cut), label + " public key data " + len);
                }
                SubjectPublicKeyInfo longerPub = new SubjectPublicKeyInfo(pubInfo.Algorithm,
                    Arrays.Append(keyData, 0x00));
                AssertRefused(() => PublicKeyFactory.CreateKey(longerPub), label + " public key data + 1");
            }
        }

        /// <summary>
        /// Single-byte changes to the same PKCS#8 encodings and SubjectPublicKeyInfos - at every one of the opening
        /// octets of a PKCS#8, where the index is, and at every third position after them: each is refused as
        /// <see cref="AllDecoders_Truncations_AreRefused"/> requires (or, for a changed algorithm OID, as
        /// unrecognised), or reads back - and a private key that reads back is never on an index below the one it was
        /// written at, which would sign again at indices already used.
        /// </summary>
        [Test]
        public void AllDecoders_ByteMutations_AreRefusedOrKeepTheirIndex()
        {
            byte[] masks = new byte[]{ 0x01, 0x80 };
            // the opening octets hold the index in every form - offset 61 in the legacy XMSS^MT one - so each of
            // them is changed, and also by 0x03, which takes an index of 3 to 0
            const int IndexWindow = 80;
            byte[] indexMasks = new byte[]{ 0x01, 0x03, 0x80 };

            foreach (string[] vector in XmssPrivateKeyEncodingTests.JavaVectors)
            {
                string label = vector[0];

                foreach (int which in new int[]{ 2, 3 })
                {
                    byte[] pkcs8 = Hex.Decode(vector[which]);
                    long index = IndexOf(PrivateKeyFactory.CreateKey(pkcs8));

                    for (int pos = 0; pos < pkcs8.Length; pos += (pos < IndexWindow) ? 1 : 3)
                    {
                        foreach (byte mask in (pos < IndexWindow) ? indexMasks : masks)
                        {
                            byte[] mutated = Arrays.Clone(pkcs8);
                            mutated[pos] ^= mask;
                            string what = label + " PKCS#8 byte " + pos + " ^ " + mask;

                            AsymmetricKeyParameter key = DecodeOrRefuse(() => PrivateKeyFactory.CreateKey(mutated),
                                what);
                            if (key != null)
                            {
                                Assert.IsTrue(IndexOf(key) >= index, what + " moved the index back");
                            }
                        }
                    }
                }

                byte[] spki = Hex.Decode(vector[1]);
                for (int pos = 0; pos < spki.Length; pos += 3)
                {
                    foreach (byte mask in masks)
                    {
                        byte[] mutated = Arrays.Clone(spki);
                        mutated[pos] ^= mask;

                        DecodeOrRefuse(() => PublicKeyFactory.CreateKey(mutated),
                            label + " SPKI byte " + pos + " ^ " + mask);
                    }
                }
            }
        }

        private static long IndexOf(AsymmetricKeyParameter key) => (key is XmssPrivateKeyParameters xmss)
            ? xmss.Index
            : ((XmssMTPrivateKeyParameters)key).Index;

        private static AsymmetricKeyParameter DecodeOrRefuse(Func<AsymmetricKeyParameter> decode, string what)
        {
            try
            {
                return decode();
            }
            catch (Exception e)
            {
                // a change to the algorithm OID leaves a key info no factory recognises, which is not an XMSS decoder
                // answering
                Assert.IsTrue(e is ArgumentException || e is InvalidOperationException
                    || e is SecurityUtilityException, what + ": " + e.GetType() + ": " + e.Message);
                return null;
            }
        }

        private static void AssertRefused(TestDelegate code, string what)
        {
            Exception thrown = null;
            try
            {
                code();
            }
            catch (Exception e)
            {
                thrown = e;
            }

            Assert.IsNotNull(thrown, what + " accepted");
            Assert.IsTrue(thrown is ArgumentException || thrown is InvalidOperationException,
                what + ": " + thrown.GetType() + ": " + thrown.Message);
        }
    }
}
