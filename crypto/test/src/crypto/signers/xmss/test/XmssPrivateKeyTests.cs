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
    /// <summary>Test cases for XmssPrivateKeyParameters class.</summary>
    /// <remarks>
    /// The methods after <see cref="TestRootCorruptionRejected"/> cover what this key and the engine under it do
    /// without a signer: Java vectors for generation, encoding, signing, sharding and recovery, and the refusals that
    /// keep a one-time key from being used twice.
    /// </remarks>
    [TestFixture]
    public class XmssPrivateKeyTests
    {
        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4 };

        [Test]
        public void TestPrivateKeyParsing()
        {
            ParsingTest(new Sha256Digest());
            ParsingTest(new Sha512Digest());
            ParsingTest(new ShakeDigest(128));
            ParsingTest(new ShakeDigest(256));
        }

        private static void ParsingTest(IDigest digest)
        {
            //
            // A generated key rather than one assembled from placeholder fields: the private key carries the tree
            // root twice - its own field and the root of its BDS state - and decode requires the two to agree
            // (bc-java github #2414), which a placeholder root does not.
            //
            XmssParameters parameters = new XmssParameters(4, digest);
            XmssPrivateKeyParameters privateKey = GenerateKey(parameters);

            byte[] export = privateKey.GetEncoded();

            XmssPrivateKeyParameters privateKey2 = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(export).Build();

            Assert.AreEqual(privateKey.Index, privateKey2.Index);
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetSecretKeySeed(), privateKey2.GetSecretKeySeed()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetSecretKeyPrf(), privateKey2.GetSecretKeyPrf()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetPublicSeed(), privateKey2.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetRoot(), privateKey2.GetRoot()));
        }

        /// <summary>
        /// A stored private key carries the tree root twice - its own field and the root of the BDS state beside it -
        /// and decode requires them to agree. Without the check a corrupted root was accepted and then poisoned every
        /// signature the key made: the root is hashed into the message digest, so the signature did not verify, with
        /// nothing to say why (bc-java github #2414).
        /// </summary>
        [Test]
        [Explicit] // slow: ~27s
        public void TestRootCorruptionRejected()
        {
            CheckRootCorruptionRejected(10);
        }

        /// <summary><see cref="TestRootCorruptionRejected"/> on a tree small enough for the default run.</summary>
        [Test]
        public void TestRootCorruptionRejected_H4()
        {
            CheckRootCorruptionRejected(4);
        }

        private static void CheckRootCorruptionRejected(int height)
        {
            int n = 32;
            XmssParameters parameters = new XmssParameters(height, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());

            XmssSigner signer = new XmssSigner();
            signer.Init(true, kp.Private);
            for (int i = 0; i != 3; i++)
            {
                XmssHarnessTests.Sign(signer, Strings.ToByteArray("message"));
            }
            XmssPrivateKeyParameters advanced = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            byte[] enc = advanced.GetEncoded();

            // index(4) | secretKeySeed(n) | secretKeyPRF(n) | publicSeed(n) | root(n) | BDS state
            int rootOff = 4 + 3 * n;
            Assert.IsTrue(Arrays.AreEqual(advanced.GetRoot(), Arrays.CopyOfRange(enc, rootOff, rootOff + n)));

            for (int b = 0; b != n; b++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                corrupt[rootOff + b] ^= 0x01;
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "no exception on corrupt root byte " + b);
                Assert.AreEqual("BDS state root does not match the private key root", e.Message);
                Assert.IsInstanceOf<InvalidOperationException>(e.InnerException);
            }

            // the untouched encoding still decodes and still signs verifiably
            XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(enc)
                .Build();
            XmssSigner s2 = new XmssSigner();
            s2.Init(true, decoded);
            byte[] sig = XmssHarnessTests.Sign(s2, Strings.ToByteArray("message"));
            XmssSigner v = new XmssSigner();
            v.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(v, Strings.ToByteArray("message"), sig));
        }

        /*
         * Java vectors: bc-java e40316b, XMSSEngine.generateKeyPair over a SecureRandom handing out 0, 1, 2, ... in
         * turn, then generateSignature(key, {1, 2, 3, 4}), extractKeyShard(3), generateSignature again, and a key
         * recovered through the builder at index 5 from the same seeds. Every key encoding is compared in full, and
         * each signature by its SHA-256.
         */

        [Test]
        public void JavaVectors_Sha256_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdSha256),
                "79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de"
                    + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                Sha256H4Priv0, "6c44752be11ff963b028d62deba6bb6b78268459d2eb0f0409dd9047e17bfa03",
                Sha256H4Priv1, Sha256H4Shard, Sha256H4Priv4,
                "3b59277bd4649f4e7503d957b30241cd4910cec91c64a1ea7764689f0c484f25", Sha256H4Rec5);
        }

        /// <summary>
        /// SHA-256/192 (SP 800-208), the one SHA-2 set whose n is shorter than the digest: every hash is truncated
        /// to its first 24 bytes, which nothing else in the default run pins to bc-java.
        /// </summary>
        [Test]
        public void JavaVectors_Sha256_192_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdSha256, 24),
                "7e241b1d628ae1cc788919e1342b5b1e2ad77fb24a99ea4f"
                    + "303132333435363738393a3b3c3d3e3f4041424344454647",
                Sha256_192H4Priv0, "7c4b941b3ead77b58f20540086e205df1cb4532f573e04663938c5e317ca82e9",
                Sha256_192H4Priv1, Sha256_192H4Shard, Sha256_192H4Priv4,
                "cb393a107d62daec146787f0f826bbe446bdc3f7ccf60010c9d90d4142784799", Sha256_192H4Rec5);
        }

        [Test]
        public void JavaVectors_Shake256_192_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdShake256Len, 24),
                "9520432a788830c7d61afac45b35ddad0d1c57e2a63b283f303132333435363738393a3b3c3d3e3f4041424344454647",
                Shake256_192H4Priv0, "da0929f506594fc957f3f2805e7abd3406b7a0dac57d45d3e684719deae9beff",
                Shake256_192H4Priv1, Shake256_192H4Shard, Shake256_192H4Priv4,
                "a66b9c4b2b883644c291dcd72e12d921a9ccf01f160ff5006c2e471e84bc2f58", Shake256_192H4Rec5);
        }

        /// <summary>A registered parameter set carries its four byte identifier in front of the public key.</summary>
        [Test]
        [Explicit] // slow: ~29s
        public void JavaVectors_XmssSha2_10_256_PublicKey()
        {
            XmssParameters parameters = XmssParameters.LookupByOid(1);
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters));

            Assert.AreEqual("0000000185055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc4"
                + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                Hex.ToHexString(((XmssPublicKeyParameters)kp.Public).GetEncoded()));
        }

        private static void CheckJavaVectors(XmssParameters parameters, string pub, string priv0, string sig0,
            string priv1, string shard, string priv4, string sig4, string rec5)
        {
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters));
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pubKey = (XmssPublicKeyParameters)kp.Public;

            Assert.AreEqual(pub, Hex.ToHexString(pubKey.GetEncoded()), "pub");
            Assert.AreEqual(priv0, Hex.ToHexString(priv.GetEncoded()), "priv0");

            byte[] signature0 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig0, XmssTestData.Sha256Hex(signature0), "sig0");
            Assert.AreEqual(priv1, Hex.ToHexString(priv.GetEncoded()), "priv1");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature0));

            XmssPrivateKeyParameters shardKey = priv.ExtractKeyShard(3);
            Assert.AreEqual(shard, Hex.ToHexString(shardKey.GetEncoded()), "shard");
            Assert.AreEqual(priv4, Hex.ToHexString(priv.GetEncoded()), "priv4");

            byte[] signature4 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig4, XmssTestData.Sha256Hex(signature4), "sig4");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature4));

            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithIndex(5).Build();
            Assert.AreEqual(rec5, Hex.ToHexString(recovered.GetEncoded()), "rec5");
            Assert.AreEqual(priv, recovered);

            // and the Java encodings read back to keys that encode the same
            foreach (string encoding in new string[]{ priv0, priv1, shard, priv4, rec5 })
            {
                XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Hex.Decode(encoding)).Build();
                Assert.AreEqual(encoding, Hex.ToHexString(decoded.GetEncoded()));
            }

            // review focus 1 on Java's bytes: the key Java stored after four signatures, decoded and signed with
            // through the signer, signs at index 4 - Java's own signature at that index, byte for byte - and moves on
            XmssPrivateKeyParameters stored4 = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(Hex.Decode(priv4)).Build();
            XmssSigner signer = new XmssSigner();
            signer.Init(true, stored4);
            byte[] resigned4 = XmssHarnessTests.Sign(signer, Message);
            Assert.AreEqual(4, XmssHarnessTests.IndexOf(resigned4));
            Assert.AreEqual(sig4, XmssTestData.Sha256Hex(resigned4), "signature from the decoded Java priv4");
            Assert.AreEqual(5, ((XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey()).Index);
            Assert.AreEqual(5, stored4.Index);
        }

        /// <summary>
        /// The state codec reports a bad encoding as an <see cref="IOException"/>; the key builder reports it as an
        /// <see cref="ArgumentException"/> with the same message, as Java wraps it in IllegalArgumentException.
        /// </summary>
        [Test]
        public void CorruptStateReportedAsArgumentException()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            int n = parameters.TreeDigestSize;
            byte[] enc = GenerateKey(parameters).GetEncoded();
            int stateOff = 4 + 4 * n;

            byte[] corrupt = Arrays.Clone(enc);
            corrupt[stateOff + 12] ^= 0x01;
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
            Assert.AreEqual("BDS state checksum does not match", e.Message);
            Assert.IsInstanceOf<IOException>(e.InnerException);

            // no state at all, and a head cut short
            e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(Arrays.CopyOfRange(enc, 0, stateOff)).Build());
            Assert.IsInstanceOf<IOException>(e.InnerException);
            for (int length = 0; length < stateOff; length += 7)
            {
                e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Arrays.CopyOfRange(enc, 0, length)).Build());
                Assert.AreEqual("private key has wrong size", e.Message);
            }

            // every truncation of the state is refused through the same exception type
            for (int length = stateOff; length < enc.Length; length++)
            {
                Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Arrays.CopyOfRange(enc, 0, length)).Build(), "length " + length);
            }
        }

        /// <summary>
        /// The stored index is bounded by 2^h before the state is read, and has to agree with the state after.
        /// </summary>
        [Test]
        public void StoredIndexChecked()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            byte[] enc = GenerateKey(parameters).GetEncoded();

            foreach (uint index in new uint[]{ 17, 0x7fffffff, 0x80000000, 0xffffffff })
            {
                byte[] corrupt = Arrays.Clone(enc);
                Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE(index, corrupt, 0);
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
                Assert.AreEqual("index out of bounds", e.Message, "index " + index);
            }

            foreach (uint index in new uint[]{ 1, 16 })
            {
                byte[] corrupt = Arrays.Clone(enc);
                Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE(index, corrupt, 0);
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
                Assert.AreEqual("BDS state has wrong index", e.Message, "index " + index);
            }
        }

        /// <summary>
        /// The used mark survives the encoding: a key rebuilt around a state that has already signed, written out and
        /// read back, is still refused at that index. (The builder path is OneTimeKeyReuseTests'
        /// testSigningIsRefusedOnAStateThatHasAlreadySigned.)
        /// </summary>
        [Test]
        public void SpentStateRefusedThroughTheEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);
            Bds captured = priv.GetBdsState();

            XmssEngine.GenerateSignature(priv, Message);
            Assert.IsTrue(captured.IsUsed, "the state the signature spent is marked");

            XmssPrivateKeyParameters replay = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(captured).Build();
            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(replay.GetEncoded()).Build();
            Assert.AreEqual(0, restored.Index);

            XmssSigner signer = new XmssSigner();
            signer.Init(true, restored);
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssHarnessTests.Sign(signer, Message));
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);
            Assert.AreEqual(0, restored.Index, "a refused signature advanced the index");
        }

        /// <summary>
        /// A key decoded from an encoding whose state carries no authentication path cannot sign, and says so
        /// rather than failing inside the traversal, before the index is advanced.
        /// </summary>
        [Test]
        public void KeyWithoutTraversalStateIsRefused()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);

            // a state with no root and no authentication path, at index 0 of the full tree
            Bds empty = new Bds(parameters, 15, 0);
            Assert.IsTrue(empty.IsAuthenticationPathEmpty);
            XmssPrivateKeyParameters key = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(empty).Build();

            Assert.IsFalse(XmssEngine.HasTraversalState(key));
            Assert.AreEqual(16, key.GetUsagesRemaining());

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(key.GetEncoded()).Build();
            Assert.IsFalse(XmssEngine.HasTraversalState(restored));

            foreach (XmssPrivateKeyParameters k in new XmssPrivateKeyParameters[]{ key, restored })
            {
                InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                    () => XmssEngine.GenerateSignature(k, Message));
                Assert.AreEqual("not initialized", e.Message);
                Assert.AreEqual(0, k.Index);
            }
        }

        /// <summary>
        /// A shard covers [index, index + usageCount) and the key it came from goes on at index + usageCount, so
        /// the two never sign at one index; asking for none, or for more than is left, is refused.
        /// </summary>
        [Test]
        public void ShardsDoNotOverlap()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            XmssPrivateKeyParameters shard = priv.ExtractKeyShard(3);
            Assert.AreEqual(0, shard.Index);
            Assert.AreEqual(3, shard.GetUsagesRemaining());
            Assert.AreEqual(3, priv.Index);
            Assert.AreEqual(13, priv.GetUsagesRemaining());

            for (int i = 0; i != 3; i++)
            {
                byte[] sig = XmssEngine.GenerateSignature(shard, Message);
                Assert.AreEqual(i, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(sig, 0));
                Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));
            }
            Assert.AreEqual(0, shard.GetUsagesRemaining());
            ExhaustedPrivateKeyException ex = Assert.Throws<ExhaustedPrivateKeyException>(
                () => XmssEngine.GenerateSignature(shard, Message));
            Assert.AreEqual("no usages of private key remaining", ex.Message);

            byte[] next = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(3, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(next, 0));
            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, next));

            ArgumentException e = Assert.Throws<ArgumentException>(() => priv.ExtractKeyShard(0));
            Assert.AreEqual("cannot ask for a shard with 0 keys", e.Message);
            e = Assert.Throws<ArgumentException>(() => priv.ExtractKeyShard(13));
            Assert.AreEqual("usageCount exceeds usages remaining", e.Message);
            Assert.AreEqual(4, priv.Index, "a refused shard moved the key");

            // the whole of what is left: the key is spent and the shard carries it all
            XmssPrivateKeyParameters rest = priv.ExtractKeyShard(12);
            Assert.AreEqual(4, rest.Index);
            Assert.AreEqual(12, rest.GetUsagesRemaining());
            Assert.AreEqual(0, priv.GetUsagesRemaining());
            Assert.AreEqual(16, priv.Index);
            Assert.Throws<ExhaustedPrivateKeyException>(() => XmssEngine.GenerateSignature(priv, Message));

            // and the spent key survives being stored
            XmssPrivateKeyParameters stored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(priv.GetEncoded()).Build();
            Assert.AreEqual(16, stored.Index);
            Assert.AreEqual(0, stored.GetUsagesRemaining());
        }

        /// <summary>A shard's limit survives the encoding: a stored shard does not widen to the whole tree.</summary>
        [Test]
        public void ShardLimitSurvivesEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);
            XmssPrivateKeyParameters shard = priv.GetNextKey();

            XmssPrivateKeyParameters stored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(shard.GetEncoded()).Build();
            Assert.AreEqual(0, stored.Index);
            Assert.AreEqual(1, stored.GetUsagesRemaining());
            Assert.AreEqual(0, stored.GetBdsState().MaxIndex);
        }

        /// <summary>
        /// A signature whose index is outside the tree - read as a signed int, a negative one - does not decode, and
        /// verification answers false for it rather than raising.
        /// </summary>
        [Test]
        public void VerifyRejectsAnIndexOutsideTheTree()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;
            byte[] sig = XmssEngine.GenerateSignature((XmssPrivateKeyParameters)kp.Private, Message);

            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));

            byte[] badIndex = Arrays.Clone(sig);
            badIndex[0] = 0x80;
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, badIndex));

            badIndex = Arrays.Clone(sig);
            badIndex[3] = 16;
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, badIndex));
        }

        // Sha256H4
        private const string Sha256H4Priv0 =
            "00000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000000001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e37bb"
                + "91630000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e400000000a52d0b6dfb3ecacce11e73071f956671699da844e9c9aa2ebd2cdd88aa1d608e";

        private const string Sha256H4Priv1 =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000010001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000200c9f44bad769c5866af8d63b5f84adaa6a404aacddef42ebc96f7e9f7460"
                + "b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e4000000010000000000000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e"
                + "37bb916392a066e6e83f80a4daf4359edbd794722d5b93d02ac5e304e4577e0476ed3d9e";

        private const string Sha256H4Shard =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "0000000200000003000000010001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000200c9f44bad769c5866af8d63b5f84adaa6a404aacddef42ebc96f7e9f7460"
                + "b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e4000000010000000000000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e"
                + "37bb91639af2b6bd12be572d39bbc6497692d4da98edde9760448038ab735e97f9e1264a";

        private const string Sha256H4Priv4 =
            "00000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000040001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de000000040000000000000020918e2cc1ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28d"
                + "b5ba00000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e4000000020000"
                + "0020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bce8d373000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "0007010101000000000000002037bb88e11581df5ff649ee5d7491f9769782800ea3f2f983c7d73bad0ee2d2d4000000"
                + "01000000010000000a01000000000001000000020000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2"
                + "d1c82df125dd902c902669e8b091005d5579250cde707ec3e84a2f830fd2e7e2238ad1f0e0c92c5a4c59f47c";

        private const string Sha256H4Rec5 =
            "00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000050001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de000000040000000000000020b3495c6e53ac466f4176d51d4ba4c5a8102d6138a24272af23c7a2bba83d"
                + "c95700000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e4000000020000"
                + "0020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bce8d373000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "0007010101000000000000002037bb88e11581df5ff649ee5d7491f9769782800ea3f2f983c7d73bad0ee2d2d4000000"
                + "01000000000000000b0100010000000000000020aa66295ea5e17ff7aadede4df773596638caa2177a8705e4855a5096"
                + "d54a369d00000002000000000000000000000020918e2cc1ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078"
                + "c28db5ba000000020000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8"
                + "b264d50fa991d34b31a2b09c657f6dda27fcba9f2c3444ecaecbcb19971d26ae";

        // Sha256_192H4
        private const string Sha256_192H4Priv0 =
            "00000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546477e241b1d628ae1cc788919e1342b5b1e2ad77fb2"
                + "4a99ea4f424453000000000100000004000000020000000f00000000000100000004000000187e241b1d628ae1cc7889"
                + "19e1342b5b1e2ad77fb24a99ea4f00000004000000000000001858a95b2997e4e1aa68830f96c9eebb06813f4be41a67"
                + "11ce0000000100000018d472fe8b719920d12304011aedb705f98040257d4a32951c000000020000001821af017ebc89"
                + "a20ad96af5fd164a865ad7e63a92a6db329e0000000300000018b45d49fce60b053514e37793ac53d6ba8e8ef9d560fc"
                + "481a00000001000000020000000100000002000000184cae3cd26fcd3dbc206db7408ad5879770e1af97a70aa93b0000"
                + "0000000000020000000000000000000000000001010000000000000018bd585362089ae95530f853d7a3291680aa7058"
                + "f40fe09523000000010000000100000000000101000000010000001833a41145becbf02968c7d2cd4e4123130df94faa"
                + "0dc70bd200000000e6d51d30d2514a12827d1bf6d66e6e5aad3bc55009f54ad4857fa79686d8b122";

        private const string Sha256_192H4Priv1 =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546477e241b1d628ae1cc788919e1342b5b1e2ad77fb2"
                + "4a99ea4f424453000000000100000004000000020000000f00000001000100000004000000187e241b1d628ae1cc7889"
                + "19e1342b5b1e2ad77fb24a99ea4f000000040000000000000018831f1e30b1befe5b6a8824ed103e76c1a8a6f051f6bc"
                + "ebbc0000000100000018d472fe8b719920d12304011aedb705f98040257d4a32951c000000020000001821af017ebc89"
                + "a20ad96af5fd164a865ad7e63a92a6db329e0000000300000018b45d49fce60b053514e37793ac53d6ba8e8ef9d560fc"
                + "481a00000001000000020000000100000002000000184cae3cd26fcd3dbc206db7408ad5879770e1af97a70aa93b0000"
                + "0000000000020000000000000000000000000001010000000000000018bd585362089ae95530f853d7a3291680aa7058"
                + "f40fe09523000000010000000100000000000101000000010000001833a41145becbf02968c7d2cd4e4123130df94faa"
                + "0dc70bd20000000100000000000000000000001858a95b2997e4e1aa68830f96c9eebb06813f4be41a6711ce07be1f03"
                + "d7791b4898282d2ce7ba9f8fc685c3a0dd794e5cb9aad52dc6e30802";

        private const string Sha256_192H4Shard =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546477e241b1d628ae1cc788919e1342b5b1e2ad77fb2"
                + "4a99ea4f424453000000000100000004000000020000000300000001000100000004000000187e241b1d628ae1cc7889"
                + "19e1342b5b1e2ad77fb24a99ea4f000000040000000000000018831f1e30b1befe5b6a8824ed103e76c1a8a6f051f6bc"
                + "ebbc0000000100000018d472fe8b719920d12304011aedb705f98040257d4a32951c000000020000001821af017ebc89"
                + "a20ad96af5fd164a865ad7e63a92a6db329e0000000300000018b45d49fce60b053514e37793ac53d6ba8e8ef9d560fc"
                + "481a00000001000000020000000100000002000000184cae3cd26fcd3dbc206db7408ad5879770e1af97a70aa93b0000"
                + "0000000000020000000000000000000000000001010000000000000018bd585362089ae95530f853d7a3291680aa7058"
                + "f40fe09523000000010000000100000000000101000000010000001833a41145becbf02968c7d2cd4e4123130df94faa"
                + "0dc70bd20000000100000000000000000000001858a95b2997e4e1aa68830f96c9eebb06813f4be41a6711ceaba7fd1f"
                + "cebe4bf5b5a1ac5a2bc9a6021bb1a6e4e6d162d9690c628fe24d601d";

        private const string Sha256_192H4Priv4 =
            "00000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546477e241b1d628ae1cc788919e1342b5b1e2ad77fb2"
                + "4a99ea4f424453000000000100000004000000020000000f00000004000100000004000000187e241b1d628ae1cc7889"
                + "19e1342b5b1e2ad77fb24a99ea4f000000040000000000000018038072c5cc8f144382158f1402f601d31b8b4cb82e15"
                + "7687000000010000001833a41145becbf02968c7d2cd4e4123130df94faa0dc70bd20000000200000018809c0b85326c"
                + "e35d8aca25b96e1590f2cc4ec46ec08173380000000300000018b45d49fce60b053514e37793ac53d6ba8e8ef9d560fc"
                + "481a00000001000000020000000100000002000000184cae3cd26fcd3dbc206db7408ad5879770e1af97a70aa93b0000"
                + "0000000000020000000000000000000000070101010000000000000018a1539e5d104b69ec46e7fb3cd9a0af0eddee09"
                + "ebe8d24f2d00000001000000010000000a0100000000000100000002000000020000001821af017ebc89a20ad96af5fd"
                + "164a865ad7e63a92a6db329e35373b24ab05574e5a09922ac442cd4454f8ee8e44fcfd0ca8efe2d6f74ae999";

        private const string Sha256_192H4Rec5 =
            "00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546477e241b1d628ae1cc788919e1342b5b1e2ad77fb2"
                + "4a99ea4f424453000000000100000004000000020000000f00000005000100000004000000187e241b1d628ae1cc7889"
                + "19e1342b5b1e2ad77fb24a99ea4f0000000400000000000000184ad982ea7d795dd5c4320fde8b3a3e8a95a2e17d653e"
                + "b0d9000000010000001833a41145becbf02968c7d2cd4e4123130df94faa0dc70bd20000000200000018809c0b85326c"
                + "e35d8aca25b96e1590f2cc4ec46ec08173380000000300000018b45d49fce60b053514e37793ac53d6ba8e8ef9d560fc"
                + "481a00000001000000020000000100000002000000184cae3cd26fcd3dbc206db7408ad5879770e1af97a70aa93b0000"
                + "0000000000020000000000000000000000070101010000000000000018a1539e5d104b69ec46e7fb3cd9a0af0eddee09"
                + "ebe8d24f2d00000001000000000000000b010001000000000000001852be4617cfe697787bff34d6e7b48e28d48e5d6c"
                + "ada2ad5700000002000000000000000000000018038072c5cc8f144382158f1402f601d31b8b4cb82e15768700000002"
                + "000000020000001821af017ebc89a20ad96af5fd164a865ad7e63a92a6db329eab40a149c9b3c6e73c6ecd72d71634d1"
                + "bc7fd7ab8ea20dab2cb2b5f4fa69ea5c";

        // Shake256_192H4
        private const string Shake256_192H4Priv0 =
            "00000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000000000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71f"
                + "ba560000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b00000000224a4ba1c2d8f790b0270c2307435cedbd5f06f9b4ba7f8c0192bb4c3e338c57";

        private const string Shake256_192H4Priv1 =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000001000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000181ef069c12d0b56f113af21b90c40fdd6bab1b7cf89a8"
                + "eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba56d2a170f7"
                + "d2c4505811b76687ee9add9bbde80d1fa203b38dd147c4a1932d2c2a";

        private const string Shake256_192H4Shard =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000300000001000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000181ef069c12d0b56f113af21b90c40fdd6bab1b7cf89a8"
                + "eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba56cc6f3f47"
                + "8e27ea5cd5ad131bc9375ffd74f838f524c43a21b28f2b65f67c1645";

        private const string Shake256_192H4Priv4 =
            "00000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000004000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000185689b488eec5f1eeff90c115d186ad9334069873ba2f"
                + "8d130000000100000018cff6571208bbe93d1c924b801f3386871ca2a718855a172b00000002000000186a11c6b653e0"
                + "68d6198a7d3d164ddd848e2f4bcf9105654e00000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000070101010000000000000018b56ca7a58980220868640cae7cbae1170c6942"
                + "235966d3a200000001000000010000000a010000000000010000000200000002000000188c821eb39580ab4bbc40e46d"
                + "158270f430b26aa7f4139267c0149f4deaad15269fbbfdd3717d30173629920af786f9b20336a01a91ae2303";

        private const string Shake256_192H4Rec5 =
            "00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000005000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000187fa037edb4177b26b0abdfdfd11e30aea1686077087d"
                + "30240000000100000018cff6571208bbe93d1c924b801f3386871ca2a718855a172b00000002000000186a11c6b653e0"
                + "68d6198a7d3d164ddd848e2f4bcf9105654e00000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000070101010000000000000018b56ca7a58980220868640cae7cbae1170c6942"
                + "235966d3a200000001000000000000000b01000100000000000000189203ff4786a60e2b02d9eb70689d4ee5fa70ee12"
                + "a8fcb7c2000000020000000000000000000000185689b488eec5f1eeff90c115d186ad9334069873ba2f8d1300000002"
                + "00000002000000188c821eb39580ab4bbc40e46d158270f430b26aa7f4139267e1ebe587c178497f4678db554e3fff2d"
                + "08c3b1cd019694c4e862d6c82f9b67ef";

        private static SecureRandom CountingRandom(XmssParameters parameters)
        {
            byte[] data = new byte[3 * parameters.TreeDigestSize];
            for (int i = 0; i != data.Length; i++)
            {
                data[i] = (byte)i;
            }
            return FixedSecureRandom.From(data);
        }

        private static AsymmetricCipherKeyPair Generate(XmssParameters parameters, SecureRandom random)
        {
            XmssKeyPairGenerator kpGen = new XmssKeyPairGenerator();
            kpGen.Init(new XmssKeyGenerationParameters(random, parameters));
            return kpGen.GenerateKeyPair();
        }

        private static XmssPrivateKeyParameters GenerateKey(XmssParameters parameters) =>
            (XmssPrivateKeyParameters)Generate(parameters, new SecureRandom()).Private;
    }
}
