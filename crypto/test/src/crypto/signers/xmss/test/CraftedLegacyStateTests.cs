using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A private key written before the versioned <see cref="BdsStateCodec"/> form carries its BDS traversal state as
    /// a bare Java serialized object. bc-java still reads that form, and hardens the read against crafted streams;
    /// this port does not read it at all (see <see cref="XmssUtilities.Deserialize"/>), so the same crafted streams
    /// are refused here before anything is built from them, as a key that will not decode: an
    /// <see cref="ArgumentException"/> out of <see cref="PrivateKeyFactory"/>, its cause the codec's
    /// <see cref="IOException"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>testCraftedXMSSStateReported</c> and <c>testCraftedXMSSMTStateReported</c> are ported with Java's own
    /// crafted streams, built byte for byte as Java builds them. <c>testCraftedNodeValueReported</c> and
    /// <c>testLegacyStateWithTrailingDataRefused</c> build their input by Java-serializing a live state, which has no
    /// C# form; they are ported onto the codec form, which is the one a crafted state can reach here.
    /// </para>
    /// <para>
    /// <c>testCraftedNullKeyInStateMapsReported</c> is not applicable: it plants a null key in a Java
    /// <c>TreeMap</c> inside a serialized state, and a serialized state of any content is refused here by
    /// <see cref="TestCraftedXmssStateReported"/>'s path. The codec form has no way to carry a null key.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class CraftedLegacyStateTests
    {
        private const byte TC_ENDBLOCKDATA = 0x78;
        private const byte TC_NULL = 0x70;
        private const byte TC_CLASSDESC = 0x72;
        private const byte TC_OBJECT = 0x73;
        private const byte TC_BLOCKDATA = 0x77;

        private const byte SC_WRITE_METHOD = 0x01;
        private const byte SC_SERIALIZABLE = 0x02;

        /// <summary>
        /// A Java serialized object naming <paramref name="className"/> and declaring no fields at all.
        /// <paramref name="trailer"/> is the class's own writeObject() data. Java's DataOutputStream layout: big-endian
        /// shorts and longs, and writeUTF's two byte length ahead of the (here ASCII) name.
        /// </summary>
        internal static byte[] FieldlessObject(string className, long serialVersionUid, byte[] trailer)
        {
            MemoryStream bOut = new MemoryStream();

            WriteShort(bOut, 0xaced);                       // STREAM_MAGIC
            WriteShort(bOut, 0x0005);                       // STREAM_VERSION

            bOut.WriteByte(TC_OBJECT);
            bOut.WriteByte(TC_CLASSDESC);
            byte[] name = Strings.ToAsciiByteArray(className);
            WriteShort(bOut, name.Length);
            bOut.Write(name, 0, name.Length);
            byte[] uid = Pack.UInt64_To_BE((ulong)serialVersionUid);
            bOut.Write(uid, 0, uid.Length);
            bOut.WriteByte(SC_WRITE_METHOD | SC_SERIALIZABLE);
            WriteShort(bOut, 0);                            // no fields
            bOut.WriteByte(TC_ENDBLOCKDATA);                // end of class annotation
            bOut.WriteByte(TC_NULL);                        // no superclass

            // no field values follow, the descriptor declared none

            bOut.WriteByte(TC_BLOCKDATA);
            bOut.WriteByte((byte)trailer.Length);
            bOut.Write(trailer, 0, trailer.Length);
            bOut.WriteByte(TC_ENDBLOCKDATA);

            return bOut.ToArray();
        }

        private static void WriteShort(MemoryStream bOut, int value)
        {
            bOut.WriteByte((byte)(value >> 8));
            bOut.WriteByte((byte)value);
        }

        /// <summary>A Java BDS whose collections are all null; its readObject() reads a four byte maximum index.
        /// </summary>
        internal static byte[] CraftedBds() =>
            FieldlessObject("org.bouncycastle.crypto.signers.xmss.BDS", 1L, new byte[]{ 0, 0, 0, 0 });

        /// <summary>A Java BDSStateMap whose map of per-layer states is null; its readObject() reads an eight byte
        /// maximum index.</summary>
        internal static byte[] CraftedBdsStateMap() =>
            FieldlessObject("org.bouncycastle.crypto.signers.xmss.BDSStateMap", -3464451825208522308L,
                new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 });

        private static void CheckRefused(PrivateKeyInfo crafted, string expectedMessage)
        {
            ArgumentException e = Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(crafted));
            Assert.AreEqual(expectedMessage, e.Message);
            Assert.IsInstanceOf<IOException>(e.InnerException);
        }

        [Test]
        public void TestCraftedXmssStateReported()
        {
            AsymmetricCipherKeyPair kp = GenerateXmss();
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            XmssPrivateKey asn1 = XmssPrivateKey.GetInstance(info.ParsePrivateKey());

            PrivateKeyInfo crafted = new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                new XmssPrivateKey(asn1.Index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                    asn1.GetPublicSeed(), asn1.GetRoot(), CraftedBds()));

            // Java: "incomplete BDS state", from its hardened legacy reader
            CheckRefused(crafted, "unrecognized BDS state encoding");
        }

        [Test]
        public void TestCraftedXmssMTStateReported()
        {
            // height 4 over 2 layers is not one of the RFC 8391 sec. 5.4 registered sets, so the key is written in
            // the legacy form that carries a state rather than the RFC 9802 raw form
            AsymmetricCipherKeyPair kp = GenerateXmssMT();
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            XmssMTPrivateKey asn1 = XmssMTPrivateKey.GetInstance(info.ParsePrivateKey());

            PrivateKeyInfo crafted = new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                new XmssMTPrivateKey(asn1.Index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                    asn1.GetPublicSeed(), asn1.GetRoot(), CraftedBdsStateMap()));

            // Java: "no state in BDS state map", from its hardened legacy reader
            CheckRefused(crafted, "unrecognized BDS state encoding");
        }

        /// <summary>
        /// A node of the wrong length in the authentication path of an otherwise sound state, its checksum recomputed
        /// - the checksum detects corruption, it does not authenticate, so a crafted state simply carries a valid one.
        /// Java reaches this shape only through its legacy reader and refuses it in BDS.validate(); the codec refuses
        /// it as it reads the node, since every node of a state shares one value size.
        /// </summary>
        [Test]
        public void TestCraftedNodeValueReported()
        {
            AsymmetricCipherKeyPair kp = GenerateXmss();
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            XmssPrivateKey asn1 = XmssPrivateKey.GetInstance(info.ParsePrivateKey());
            byte[] publicSeed = asn1.GetPublicSeed();
            byte[] state = asn1.GetBdsState();
            int n = publicSeed.Length;

            // magic, version, height, k, max index, index, used, root present, root height, root size, root, count
            int nodeSizeOffset = 8 + 4 * 4 + 1 + 1 + 4 + 4 + n + 4 + 4;
            Assert.AreEqual(n, (int)Pack.BE_To_UInt32(state, nodeSizeOffset));

            byte[] body = Arrays.ConcatenateAll(Arrays.CopyOfRange(state, 0, nodeSizeOffset),
                Pack.UInt32_To_BE((uint)(n - 1)),
                Arrays.CopyOfRange(state, nodeSizeOffset + 4, nodeSizeOffset + 4 + n - 1));
            body = Arrays.Concatenate(body,
                Arrays.CopyOfRange(state, nodeSizeOffset + 4 + n, state.Length - 32));

            PrivateKeyInfo crafted = new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                new XmssPrivateKey(asn1.Index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                    publicSeed, asn1.GetRoot(), WithChecksum(body, publicSeed)));

            // Java: "malformed XMSS private key: XMSS node in BDS state out of bounds"
            CheckRefused(crafted, "inconsistent XMSS node value sizes");
        }

        /// <summary>
        /// A state carrying a byte past its end is a second encoding of the same state, and is refused for both
        /// families, while the unpadded encoding is still taken. On the codec form, with the checksum recomputed over
        /// the padded body.
        /// </summary>
        [Test]
        public void TestLegacyStateWithTrailingDataRefused()
        {
            AsymmetricCipherKeyPair mtKp = GenerateXmssMT();
            PrivateKeyInfo mtInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(mtKp.Private);
            XmssMTPrivateKey mtAsn1 = XmssMTPrivateKey.GetInstance(mtInfo.ParsePrivateKey());
            byte[] mtState = mtAsn1.GetBdsState();

            Assert.IsNotNull(PrivateKeyFactory.CreateKey(new PrivateKeyInfo(mtInfo.PrivateKeyAlgorithm,
                new XmssMTPrivateKey(mtAsn1.Index, mtAsn1.GetSecretKeySeed(), mtAsn1.GetSecretKeyPrf(),
                    mtAsn1.GetPublicSeed(), mtAsn1.GetRoot(), mtState))), "the unpadded state map is not read");

            byte[] mtPadded = WithChecksum(Arrays.Append(Arrays.CopyOfRange(mtState, 0, mtState.Length - 32), 0xff),
                mtAsn1.GetPublicSeed());
            CheckRefused(new PrivateKeyInfo(mtInfo.PrivateKeyAlgorithm,
                new XmssMTPrivateKey(mtAsn1.Index, mtAsn1.GetSecretKeySeed(), mtAsn1.GetSecretKeyPrf(),
                    mtAsn1.GetPublicSeed(), mtAsn1.GetRoot(), mtPadded)), "unexpected data at end of BDS state");

            AsymmetricCipherKeyPair kp = GenerateXmss();
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            XmssPrivateKey asn1 = XmssPrivateKey.GetInstance(info.ParsePrivateKey());
            byte[] state = asn1.GetBdsState();

            Assert.IsNotNull(PrivateKeyFactory.CreateKey(new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                new XmssPrivateKey(asn1.Index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                    asn1.GetPublicSeed(), asn1.GetRoot(), state))), "the unpadded state is not read");

            byte[] padded = WithChecksum(Arrays.Append(Arrays.CopyOfRange(state, 0, state.Length - 32), 0xff),
                asn1.GetPublicSeed());
            CheckRefused(new PrivateKeyInfo(info.PrivateKeyAlgorithm,
                new XmssPrivateKey(asn1.Index, asn1.GetSecretKeySeed(), asn1.GetSecretKeyPrf(),
                    asn1.GetPublicSeed(), asn1.GetRoot(), padded)), "unexpected data at end of BDS state");
        }

        /// <summary>The state body followed by its checksum, SHA-256 over the public seed and the body.</summary>
        internal static byte[] WithChecksum(byte[] body, byte[] publicSeed)
        {
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(publicSeed, 0, publicSeed.Length);
            digest.BlockUpdate(body, 0, body.Length);
            byte[] sum = new byte[digest.GetDigestSize()];
            digest.DoFinal(sum, 0);
            return Arrays.Concatenate(body, sum);
        }

        private static AsymmetricCipherKeyPair GenerateXmss()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();
            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(4, NistObjectIdentifiers.IdSha256)));
            return kpg.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateXmssMT()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, NistObjectIdentifiers.IdSha256)));
            return kpg.GenerateKeyPair();
        }
    }
}
