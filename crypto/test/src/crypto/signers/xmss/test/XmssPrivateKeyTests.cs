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
    /// testRootCorruptionRejected signs through XmssSigner and arrives with it. The methods after
    /// <see cref="TestPrivateKeyParsing"/> cover what this key and the engine under it do without a signer: Java
    /// vectors for generation, encoding, signing, sharding and recovery, and the refusals that keep a one-time key
    /// from being used twice.
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

        /*
         * Java vectors: bc-java e40316b, XMSSEngine.generateKeyPair over a SecureRandom handing out 0, 1, 2, ... in
         * turn, then generateSignature(key, {1, 2, 3, 4}), extractKeyShard(3), generateSignature again, and a key
         * recovered through the builder at index 5 from the same seeds. Encodings longer than a public key are
         * compared by their SHA-256.
         */

        [Test]
        public void JavaVectors_Sha256_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdSha256),
                "79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de"
                    + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                "3ffc5c5cd0d221517c27d61062323b988be9075aea02b6428cfd0944dda4a43c",
                "6c44752be11ff963b028d62deba6bb6b78268459d2eb0f0409dd9047e17bfa03",
                "b6eb4b45dff6c61d066ade422596ee865216698cb02d22dbfaf0cf3aeb2cd820",
                "b68235413c26589cef5ed6db8a0c60f96b982a6c1588dfbac8a1fe011261763b",
                "dc1d5696eab1b254123c6570de1ddb9b3f486763d7f3d38fd90dd32afc500708",
                "3b59277bd4649f4e7503d957b30241cd4910cec91c64a1ea7764689f0c484f25",
                "94df82522c66106b6cde3b65f8492f1de1bd2e6afed7073fa1eec75bbdf9da7c");
        }

        [Test]
        public void JavaVectors_Shake256_192_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdShake256Len, 24),
                "9520432a788830c7d61afac45b35ddad0d1c57e2a63b283f303132333435363738393a3b3c3d3e3f4041424344454647",
                "e6bc41d299e921e709d3ee9ac03ad821e3d1d9e0aac3141048b7b8562637215d",
                "da0929f506594fc957f3f2805e7abd3406b7a0dac57d45d3e684719deae9beff",
                "974823965a37cd8fbe69bb151da994ed12f551e40406ea5d6dd8ab5d92ce3644",
                "1f95b7591257350230393fb0444a7ea1e94c2008ff8922fa8eea89202addcb04",
                "bde2c435f2b7b4c2f063e76b0d1f94cd976c3255048bc206ba52cf1c2a6d04b5",
                "a66b9c4b2b883644c291dcd72e12d921a9ccf01f160ff5006c2e471e84bc2f58",
                "4bf3429e1a28129365f4f0c2bf1d0bff399482355439b89544e82614f086d909");
        }

        /// <summary>A registered parameter set carries its four byte identifier in front of the public key.</summary>
        [Test]
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
            Assert.AreEqual(priv0, Sha256Hex(priv.GetEncoded()), "priv0");

            byte[] signature0 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig0, Sha256Hex(signature0), "sig0");
            Assert.AreEqual(priv1, Sha256Hex(priv.GetEncoded()), "priv1");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature0));

            XmssPrivateKeyParameters shardKey = priv.ExtractKeyShard(3);
            Assert.AreEqual(shard, Sha256Hex(shardKey.GetEncoded()), "shard");
            Assert.AreEqual(priv4, Sha256Hex(priv.GetEncoded()), "priv4");

            byte[] signature4 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig4, Sha256Hex(signature4), "sig4");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature4));

            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithIndex(5).Build();
            Assert.AreEqual(rec5, Sha256Hex(recovered.GetEncoded()), "rec5");
            Assert.AreEqual(priv, recovered);

            // and the Java encodings read back to keys that encode the same
            XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(priv.GetEncoded()).Build();
            Assert.AreEqual(priv4.Length, Sha256Hex(decoded.GetEncoded()).Length);
            Assert.AreEqual(Sha256Hex(recovered.GetEncoded()), Sha256Hex(decoded.GetEncoded()));
        }

        /// <summary>
        /// A stored key's root is checked against the root of its traversal state, and a mismatch is reported as
        /// an <see cref="ArgumentException"/> carrying the state's own message. The Java method signs three times
        /// first; this is the same check on a key that has not signed.
        /// </summary>
        [Test]
        public void RootCorruptionRejected_Unsigned()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            int n = parameters.TreeDigestSize;
            byte[] enc = GenerateKey(parameters).GetEncoded();

            int rootOff = 4 + 3 * n;
            for (int b = 0; b != n; b++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                corrupt[rootOff + b] ^= 0x01;
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
                Assert.AreEqual("BDS state root does not match the private key root", e.Message);
                Assert.IsInstanceOf<InvalidOperationException>(e.InnerException);
            }
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
        /// Each signature consumes the index it was made at and leaves the key on the next one, and an encoding of
        /// the key taken after N signatures signs at N, never earlier.
        /// </summary>
        [Test]
        public void SigningAdvancesTheKeyAndTheEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            for (int i = 0; i != 3; i++)
            {
                Assert.AreEqual(i, priv.Index);
                Assert.AreEqual(16 - i, priv.GetUsagesRemaining());
                byte[] sig = XmssEngine.GenerateSignature(priv, Message);
                Assert.AreEqual(i, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(sig, 0));
                Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));
            }

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(priv.GetEncoded()).Build();
            Assert.AreEqual(3, restored.Index);
            byte[] next = XmssEngine.GenerateSignature(restored, Message);
            Assert.AreEqual(3, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(next, 0));
            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, next));
        }

        /// <summary>
        /// A traversal state handed in through the builder is copied, so a signature by one key cannot mark the
        /// state of another; and a state already marked used is refused before anything is signed or advanced.
        /// </summary>
        [Test]
        public void UsedStateIsRefused()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);
            Bds captured = priv.GetBdsState();

            XmssPrivateKeyParameters twin = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(captured).Build();
            Assert.AreNotSame(captured, twin.GetBdsState());

            XmssEngine.GenerateSignature(priv, Message);
            Assert.IsTrue(captured.IsUsed, "the state the signature spent is marked");
            Assert.IsFalse(twin.GetBdsState().IsUsed, "a copy shares no mark");

            // a key put back on the spent state through the builder is refused at that index
            XmssPrivateKeyParameters replay = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(captured).Build();
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssEngine.GenerateSignature(replay, Message));
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);
            Assert.AreEqual(0, replay.Index, "a refused signature advanced the index");

            // the same through an encoding of the spent state
            byte[] stored = replay.GetEncoded();
            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(stored).Build();
            e = Assert.Throws<InvalidOperationException>(() => XmssEngine.GenerateSignature(restored, Message));
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);
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

        /// <summary>Verification answers false for a signature that does not decode, and raises for none.</summary>
        [Test]
        public void VerifyRejectsMalformedSignatures()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;
            byte[] sig = XmssEngine.GenerateSignature((XmssPrivateKeyParameters)kp.Private, Message);

            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));
            Assert.IsFalse(XmssEngine.VerifySignature(pub, new byte[]{ 1, 2, 3, 5 }, sig));
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, Arrays.CopyOfRange(sig, 0, sig.Length - 1)));
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, Arrays.Append(sig, 0)));
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, new byte[0]));

            byte[] badIndex = Arrays.Clone(sig);
            badIndex[0] = 0x80;
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, badIndex));

            Assert.Throws<ArgumentNullException>(() => XmssEngine.VerifySignature(pub, Message, null));
        }

        private static string Sha256Hex(byte[] data)
        {
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] output = new byte[32];
            digest.DoFinal(output, 0);
            return Hex.ToHexString(output);
        }

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
