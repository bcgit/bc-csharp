using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The legacy key encodings (<see cref="XmssKeyParams"/> / <see cref="XmssMTKeyParams"/> parameters, with the
    /// <see cref="XmssPrivateKey"/> / <see cref="XmssMTPrivateKey"/> body) are written for any parameter set with no
    /// parameter set OID. These are the checks that keep what is written there readable, and what is read from there
    /// within the range the key was given.
    /// </summary>
    [TestFixture]
    public class LegacyKeyEncodingTests
    {
        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4 };

        /// <summary>
        /// The legacy parameters name the tree digest and not n, so a key is read back with n equal to the digest's
        /// natural output size. A key with an explicit n other than that, at a height with no parameter set OID,
        /// is refused when it is written, not when it is read.
        /// </summary>
        [Test]
        public void TestXmssWithNonNaturalNIsRefusedAtEncode()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(4, NistObjectIdentifiers.IdSha256, 24)));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            Assert.Throws<ArgumentException>(() => PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));
            Assert.Throws<ArgumentException>(() => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
        }

        /// <summary>The XMSS^MT counterpart of <see cref="TestXmssWithNonNaturalNIsRefusedAtEncode"/>.</summary>
        [Test]
        public void TestXmssMTWithNonNaturalNIsRefusedAtEncode()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, NistObjectIdentifiers.IdSha256, 24)));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            Assert.Throws<ArgumentException>(() => PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));
            Assert.Throws<ArgumentException>(() => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
        }

        /// <summary>
        /// And the natural n still goes through the legacy form and comes back, the same key.
        /// </summary>
        [Test]
        public void TestNaturalNStillRoundTrips()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(4, new Sha256Digest())));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            byte[] encoded = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private).GetEncoded();
            XmssPrivateKeyParameters back = (XmssPrivateKeyParameters)PrivateKeyFactory.CreateKey(encoded);

            Assert.AreEqual(32, back.Parameters.TreeDigestSize);
            Assert.AreEqual(((XmssPrivateKeyParameters)kp.Private).GetEncoded(), back.GetEncoded());
        }

        /// <summary>
        /// <see cref="XmssPrivateKey"/> accepts the <c>[0] maxIndex</c> field at version 0 as well as at version 1,
        /// so the field is honoured whatever the version says. A stateless shard read back without it would be
        /// widened to the whole tree, overlapping the key it was taken from; with it, the shard's state is rebuilt
        /// over the whole tree and is refused for not reflecting the bound, as it is at version 1.
        /// </summary>
        [Test]
        public void TestXmssVersionZeroMaxIndexIsNotDropped()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(4, new Sha256Digest())));
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kpg.GenerateKeyPair().Private);
            XmssPrivateKey asn1 = XmssPrivateKey.GetInstance(info.ParsePrivateKey());

            Asn1Sequence keyData = new DerSequence(DerInteger.ValueOf(asn1.Index),
                new DerOctetString(asn1.GetSecretKeySeed()), new DerOctetString(asn1.GetSecretKeyPrf()),
                new DerOctetString(asn1.GetPublicSeed()), new DerOctetString(asn1.GetRoot()),
                new DerTaggedObject(false, 0, DerInteger.ValueOf(1)));

            CheckShardRefused(info, keyData);
        }

        /// <summary>The XMSS^MT counterpart of <see cref="TestXmssVersionZeroMaxIndexIsNotDropped"/>.</summary>
        [Test]
        public void TestXmssMTVersionZeroMaxIndexIsNotDropped()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, new Sha256Digest())));
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kpg.GenerateKeyPair().Private);
            XmssMTPrivateKey asn1 = XmssMTPrivateKey.GetInstance(info.ParsePrivateKey());

            Asn1Sequence keyData = new DerSequence(DerInteger.ValueOf(asn1.Index),
                new DerOctetString(asn1.GetSecretKeySeed()), new DerOctetString(asn1.GetSecretKeyPrf()),
                new DerOctetString(asn1.GetPublicSeed()), new DerOctetString(asn1.GetRoot()),
                new DerTaggedObject(false, 0, DerInteger.ValueOf(1)));

            CheckShardRefused(info, keyData);
        }

        /// <summary>
        /// The version says whether <c>[0] maxIndex</c> is there, and the structures write it back from the field: a
        /// version 1 body without the field is refused rather than read and written back as version 0, and a
        /// negative maximum index is refused by the constructor that writes one.
        /// </summary>
        [Test]
        public void TestVersionOneWithoutMaxIndexIsRefused()
        {
            byte[] n32 = new byte[32];
            Asn1Sequence keyData = new DerSequence(DerInteger.ValueOf(3), new DerOctetString(n32),
                new DerOctetString(n32), new DerOctetString(n32), new DerOctetString(n32));
            Asn1Sequence versionOne = new DerSequence(DerInteger.One, keyData);
            Asn1Sequence versionZero = new DerSequence(DerInteger.Zero, keyData);

            ArgumentException e = Assert.Throws<ArgumentException>(() => XmssPrivateKey.GetInstance(versionOne));
            Assert.AreEqual("version 1 key without maxIndex", e.Message);
            e = Assert.Throws<ArgumentException>(() => XmssMTPrivateKey.GetInstance(versionOne));
            Assert.AreEqual("version 1 key without maxIndex", e.Message);

            Assert.AreEqual(versionZero.GetEncoded(), XmssPrivateKey.GetInstance(versionZero).GetEncoded());
            Assert.AreEqual(versionZero.GetEncoded(), XmssMTPrivateKey.GetInstance(versionZero).GetEncoded());

            Assert.Throws<ArgumentException>(() => new XmssPrivateKey(3, n32, n32, n32, n32, null, -1));
            Assert.Throws<ArgumentException>(() => new XmssMTPrivateKey(3L, n32, n32, n32, n32, null, -1L));
        }

        private static void CheckShardRefused(PrivateKeyInfo info, Asn1Sequence keyData)
        {
            foreach (int version in new int[]{ 0, 1 })
            {
                PrivateKeyInfo shard = new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                    new DerSequence(DerInteger.ValueOf(version), keyData));

                ArgumentException e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(shard),
                    "version " + version);
                StringAssert.EndsWith("maxIndex set but not reflected in state", e.Message, "version " + version);
            }
        }

        /// <summary>
        /// The legacy XMSS^MT body carries the index and the state map side by side, and the state map agrees with
        /// any index 2^h away from the right one on every layer. An index outside 0 to maxIndex + 1 is refused.
        /// </summary>
        [Test]
        public void TestXmssMTIndexOutOfRangeIsRefusedAtDecode()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricKeyParameter key = kpg.GenerateKeyPair().Private;

            XmssEngine.GenerateMTSignature((XmssMTPrivateKeyParameters)key, Message);

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key);
            XmssMTPrivateKey asn1 = XmssMTPrivateKey.GetInstance(info.ParsePrivateKey());
            long span = 1L << parameters.Height;

            Assert.IsNotNull(PrivateKeyFactory.CreateKey(info), "the key as written");

            foreach (long index in new long[]{ asn1.Index - span, asn1.Index + span })
            {
                PrivateKeyInfo crafted = new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                    new XmssMTPrivateKey(index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                        asn1.GetPublicSeed(), asn1.GetRoot(), asn1.GetBdsState()));

                Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(crafted), "index " + index);
            }
        }
    }
}
