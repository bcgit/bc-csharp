using System;
using System.Diagnostics;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>The XMSS / XMSS^MT key parameter builders.</summary>
    /// <remarks>
    /// The Java tests are written in XMSS / XMSS^MT pairs, and both halves are here, except where a remark says
    /// otherwise.
    /// </remarks>
    [TestFixture]
    public class KeyParametersBuilderTests
    {
        private const int Height = 4;
        private const int Layers = 2;

        private static XmssParameters XmssParams() => new XmssParameters(Height, new Sha256Digest());

        private static XmssMTParameters XmssMTParams() => new XmssMTParameters(Height, Layers, new Sha256Digest());

        /// <summary>The root the seeds compute, which a key built from them must declare.</summary>
        private static byte[] RootOf(XmssParameters parameters, byte[] secretKeySeed, byte[] publicSeed) =>
            new Bds(parameters, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0)).Root.GetValue();

        /// <summary>The XMSS^MT root the seeds compute: the root of the top layer's first tree.</summary>
        private static byte[] MTRootOf(XmssMTParameters parameters, byte[] secretKeySeed, byte[] publicSeed) =>
            new Bds(parameters.XmssParameters, publicSeed, secretKeySeed,
                XmssAddress.OtsHashAddress(parameters.Layers - 1, 0L, 0)).Root.GetValue();

        /// <summary>A null parameter set is rejected where it is passed. All builders share the wording.</summary>
        [Test]
        public void TestNullParametersRejectedByBuilder()
        {
            ArgumentNullException e = Assert.Throws<ArgumentNullException>(
                () => new XmssPrivateKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);

            e = Assert.Throws<ArgumentNullException>(() => new XmssPublicKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);

            e = Assert.Throws<ArgumentNullException>(() => new XmssMTPrivateKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);

            e = Assert.Throws<ArgumentNullException>(() => new XmssMTPublicKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);
        }

        /// <summary>
        /// The signature builder reads an index out of the encoding and it can name a leaf the tree does not have,
        /// or - read as a signed int - a negative one. Both are refused at the builder.
        /// </summary>
        [Test]
        public void TestSignatureIndexOutsideTheTreeRejectedByBuilder()
        {
            XmssParameters parameters = XmssParams();
            // index(4) || random(n) || reduced signature, as XmssSignature lays it down
            int size = 4 + parameters.TreeDigestSize + XmssReducedSignature.SizeOf(parameters);
            int[] outside = new int[]{ 1 << Height, (1 << Height) + 1, int.MaxValue, -1, int.MinValue };

            for (int i = 0; i != outside.Length; i++)
            {
                byte[] encoded = new byte[size];

                Pack.UInt32_To_BE((uint)outside[i], encoded, 0);

                try
                {
                    new XmssSignature.Builder(parameters).WithSignature(encoded).Build();
                    Assert.Fail("index " + outside[i] + " accepted");
                }
                catch (ArgumentException e)
                {
                    Assert.AreEqual("index out of bounds", e.Message);
                }
                catch (InvalidOperationException e)
                {
                    // IsIndexValid raises rather than returns for a negative index
                    Assert.AreEqual("index must not be negative", e.Message);
                    Assert.IsTrue(outside[i] < 0, "only the negative cases arrive this way");
                }
            }

            // every index the tree does have still decodes, so the bound is where the tree ends
            for (int index = 0; index != (1 << Height); index++)
            {
                byte[] encoded = new byte[size];

                Pack.UInt32_To_BE((uint)index, encoded, 0);

                Assert.AreEqual(index, new XmssSignature.Builder(parameters).WithSignature(encoded).Build().Index);
            }
        }

        /// <summary>
        /// The key builders, and the signature builder beside them, take the same optional n-byte fields on the same
        /// terms, so a wrong-sized one is reported the same way.
        /// </summary>
        [Test]
        public void TestWrongSizedFieldRejectedByBuilder()
        {
            byte[] shortSeed = new byte[31];
            byte[] seed = new byte[32];

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssSignature.Builder(XmssParams()).WithRandom(shortSeed).Build());
            Assert.AreEqual("size of random needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(
                () => new XmssMTSignature.Builder(XmssMTParams()).WithRandom(shortSeed).Build());
            Assert.AreEqual("size of random needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssPublicKeyParameters.Builder(XmssParams())
                .WithRoot(shortSeed).WithPublicSeed(seed).Build());
            Assert.AreEqual("size of root needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssMTPublicKeyParameters.Builder(XmssMTParams())
                .WithRoot(seed).WithPublicSeed(shortSeed).Build());
            Assert.AreEqual("size of publicSeed needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(XmssParams())
                .WithSecretKeySeed(shortSeed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed).Build());
            Assert.AreEqual("size of secretKeySeed needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssMTPrivateKeyParameters.Builder(XmssMTParams())
                .WithSecretKeySeed(seed).WithSecretKeyPrf(shortSeed).WithPublicSeed(seed).WithRoot(seed).Build());
            Assert.AreEqual("size of secretKeyPRF needs to be equal to size of digest", e.Message);
        }

        /// <summary>The private key builder will not hand back a key whose seeds it had to invent.</summary>
        [Test]
        public void TestPrivateKeyWithoutSeedsRejected()
        {
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => new XmssPrivateKeyParameters.Builder(XmssParams()).Build());
            Assert.AreEqual("publicSeed or secretKeySeed is null", e.Message);

            e = Assert.Throws<InvalidOperationException>(
                () => new XmssMTPrivateKeyParameters.Builder(XmssMTParams()).Build());
            Assert.AreEqual("publicSeed or secretKeySeed is null", e.Message);
        }

        /// <summary>The seed check is a disjunction - an imported private key carries its own seeds.</summary>
        [Test]
        public void TestPrivateKeyImportStillAccepted()
        {
            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(XmssParams())
                .WithPrivateKey(xmss.GetEncoded()).Build();
            Assert.IsTrue(Arrays.AreEqual(xmss.GetEncoded(), recovered.GetEncoded()));

            XmssMTPrivateKeyParameters mt = (XmssMTPrivateKeyParameters)GenerateXmssMT().Private;
            XmssMTPrivateKeyParameters mtRecovered = new XmssMTPrivateKeyParameters.Builder(XmssMTParams())
                .WithPrivateKey(mt.GetEncoded()).Build();
            Assert.IsTrue(Arrays.AreEqual(mt.GetEncoded(), mtRecovered.GetEncoded()));
        }

        /// <summary>A generated key can be used 2^h times.</summary>
        [Test]
        public void TestGeneratedKeysReportFullUsageCount()
        {
            long expected = 1L << Height;

            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            Assert.AreEqual(expected, xmss.GetUsagesRemaining());
            Assert.AreEqual(expected - 1, xmss.GetBdsState().MaxIndex);

            XmssMTPrivateKeyParameters mt = (XmssMTPrivateKeyParameters)GenerateXmssMT().Private;
            Assert.AreEqual(expected, mt.GetUsagesRemaining());
            Assert.AreEqual(expected - 1, mt.GetBdsState().MaxIndex);
        }

        /// <summary>
        /// RollKey() past the last leaf installs the placeholder state - index one past the maximum index - so the
        /// key reports zero usages rather than wrapping round and reusing a one-time key.
        /// </summary>
        [Test]
        public void TestRollKeyPastLastLeafExhaustsTheKey()
        {
            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)GenerateXmss().Private;

            long maxIndex = key.GetBdsState().MaxIndex;
            for (int i = 0; i != (1 << Height); i++)
            {
                key = key.RollKey();
            }

            Assert.AreEqual(0, key.GetUsagesRemaining());
            Assert.AreEqual(maxIndex + 1, key.Index);

            // and it stays exhausted rather than wrapping
            key = key.RollKey();
            Assert.AreEqual(0, key.GetUsagesRemaining());
            Assert.AreEqual(maxIndex + 1, key.Index);
        }

        /// <summary>
        /// An index past the end of the tree is refused before the tree is walked to rebuild the lost state, rather
        /// than by the walk once it runs out of tree.
        /// </summary>
        [Test]
        public void TestRecoveryIndexCheckedBeforeTheTreeIsWalked()
        {
            XmssParameters parameters = XmssParams();
            byte[] seed = new byte[parameters.TreeDigestSize];
            int[] outOfRange = new int[]{ -1, (1 << Height) + 1, int.MaxValue };

            for (int i = 0; i != outOfRange.Length; i++)
            {
                Stopwatch started = Stopwatch.StartNew();

                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => RecoverXmssAt(parameters, seed, outOfRange[i]), "index " + outOfRange[i] + " accepted");
                Assert.AreEqual("index out of bounds", e.Message);

                // the point of the check is that no walk happens at all, so any sane bound catches a regression
                Assert.IsTrue(started.ElapsedMilliseconds < 5000, "index " + outOfRange[i] + " was walked");
            }
        }

        /// <summary>
        /// 2^h is the index of a key with every leaf spent. It is inside the range the encoded-key path accepts and is
        /// what RollKey() leaves behind, so a state the encoding can carry can be rebuilt - and it cannot sign.
        /// </summary>
        [Test]
        public void TestRecoveryAtTheExhaustedIndex()
        {
            XmssParameters parameters = XmssParams();
            byte[] seed = new byte[parameters.TreeDigestSize];

            XmssPrivateKeyParameters spent = RecoverXmssAt(parameters, seed, 1 << Height);

            Assert.AreEqual(1 << Height, spent.Index);
            Assert.AreEqual(0, spent.GetUsagesRemaining());
            Assert.AreEqual((1 << Height) - 1, spent.GetBdsState().MaxIndex);

            XmssSigner signer = new XmssSigner();

            signer.Init(true, spent);
            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

            ExhaustedPrivateKeyException e = Assert.Throws<ExhaustedPrivateKeyException>(
                () => signer.GenerateSignature(), "spent key signed");
            Assert.AreEqual("no usages of private key remaining", e.Message);
        }

        /// <summary>
        /// A shard covers the range [index...index + usageCount), so the single use shard GetNextKey() takes from an
        /// unused key covers index 0 alone and carries maximum index 0: it signs once, and then it is spent.
        /// </summary>
        [Test]
        public void TestSingleUseShardCoversOneSignature()
        {
            byte[] message = new byte[]{ 1, 2, 3 };

            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            XmssPrivateKeyParameters xmssShard = xmss.GetNextKey();

            Assert.AreEqual(0, xmssShard.Index);
            Assert.AreEqual(0, xmssShard.GetBdsState().MaxIndex);
            Assert.AreEqual(1, xmssShard.GetUsagesRemaining());
            Assert.AreEqual(1, xmss.Index);

            XmssSigner signer = new XmssSigner();

            signer.Init(true, xmssShard);
            signer.BlockUpdate(message, 0, message.Length);
            signer.GenerateSignature();

            signer.BlockUpdate(message, 0, message.Length);

            ExhaustedPrivateKeyException e = Assert.Throws<ExhaustedPrivateKeyException>(
                () => signer.GenerateSignature());
            Assert.AreEqual("no usages of private key remaining", e.Message);

            AsymmetricCipherKeyPair mtKp = GenerateXmssMT();
            XmssMTPrivateKeyParameters mt = (XmssMTPrivateKeyParameters)mtKp.Private;
            XmssMTPrivateKeyParameters mtShard = mt.GetNextKey();

            Assert.AreEqual(0, mtShard.Index);
            Assert.AreEqual(0, mtShard.GetBdsState().MaxIndex);
            Assert.AreEqual(1, mtShard.GetUsagesRemaining());
            Assert.AreEqual(1, mt.Index);

            // maximum index 0 now means what it says, so it has to survive being written out and read back: the
            // encoding records a maximum index short of the tree's, where one covering the whole tree is left to the
            // reader to infer
            XmssMTPrivateKeyParameters restored = (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(mtShard).GetEncoded());

            Assert.AreEqual(0, restored.Index);
            Assert.AreEqual(1, restored.GetUsagesRemaining());

            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(true, mtShard);
            mtSigner.BlockUpdate(message, 0, message.Length);
            byte[] mtSignature = mtSigner.GenerateSignature();

            XmssMTSigner mtVerifier = new XmssMTSigner();
            mtVerifier.Init(false, mtKp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(mtVerifier, message, mtSignature), "the shard's signature");

            mtSigner.BlockUpdate(message, 0, message.Length);

            e = Assert.Throws<ExhaustedPrivateKeyException>(() => mtSigner.GenerateSignature());
            Assert.AreEqual("no usages of private key remaining", e.Message);
        }

        /// <summary>
        /// The XMSS^MT half of <see cref="TestRecoveryIndexCheckedBeforeTheTreeIsWalked"/>. An index the hypertree
        /// cannot hold is refused rather than falling through to a placeholder state map that nothing downstream
        /// can tell from a legitimate one: XMSS^MT builds each layer's state lazily, so a map with no layers in it
        /// passes both the structural check and the per-layer index check.
        /// </summary>
        [Test]
        public void TestMTRecoveryIndexCheckedBeforeTheTreeIsWalked()
        {
            XmssMTParameters parameters = XmssMTParams();
            byte[] seed = new byte[parameters.TreeDigestSize];
            long[] outOfRange = new long[]{ -1L, (1L << Height) + 1, long.MaxValue };

            for (int i = 0; i != outOfRange.Length; i++)
            {
                Stopwatch started = Stopwatch.StartNew();

                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => RecoverXmssMTAt(parameters, seed, outOfRange[i]), "index " + outOfRange[i] + " accepted");
                Assert.AreEqual("index out of bounds", e.Message);

                Assert.IsTrue(started.ElapsedMilliseconds < 5000, "index " + outOfRange[i] + " was walked");
            }
        }

        /// <summary>
        /// The XMSS^MT half of <see cref="TestRecoveryAtTheExhaustedIndex"/>: 2^h is in range and is the position
        /// RollKey() stops at, so it rebuilds to the state RollKey() leaves behind - an empty map whose maximum index
        /// is the last leaf - which refuses to sign.
        /// </summary>
        [Test]
        public void TestMTRecoveryAtTheExhaustedIndex()
        {
            XmssMTParameters parameters = XmssMTParams();
            byte[] seed = new byte[parameters.TreeDigestSize];

            XmssMTPrivateKeyParameters spent = RecoverXmssMTAt(parameters, seed, 1L << Height);

            Assert.AreEqual(1L << Height, spent.Index);
            Assert.AreEqual(0, spent.GetUsagesRemaining());
            Assert.AreEqual((1L << Height) - 1, spent.GetBdsState().MaxIndex);

            XmssMTSigner signer = new XmssMTSigner();

            signer.Init(true, spent);
            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

            ExhaustedPrivateKeyException e = Assert.Throws<ExhaustedPrivateKeyException>(
                () => signer.GenerateSignature(), "spent key signed");
            Assert.AreEqual("no usages of private key remaining", e.Message);
            Assert.AreEqual(1L << Height, spent.Index, "a refused signature moved the key");
        }

        /// <summary>A generator asked for a key pair before Init() says so rather than dereferencing nothing.</summary>
        [Test]
        public void GenerateKeyPairBeforeInitRefused()
        {
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => new XmssKeyPairGenerator().GenerateKeyPair());
            Assert.AreEqual("XmssKeyPairGenerator not initialised", e.Message);
        }

        /// <summary>As <see cref="GenerateKeyPairBeforeInitRefused"/>, for the XMSS^MT generator.</summary>
        [Test]
        public void MTGenerateKeyPairBeforeInitRefused()
        {
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => new XmssMTKeyPairGenerator().GenerateKeyPair());
            Assert.AreEqual("XmssMTKeyPairGenerator not initialised", e.Message);
        }

        /// <summary>A maxIndex given to the builder has to be the one the state carries.</summary>
        [Test]
        public void MaxIndexNotReflectedInStateRejected()
        {
            XmssParameters parameters = XmssParams();
            byte[] seed = new byte[parameters.TreeDigestSize];
            byte[] root = RootOf(parameters, seed, seed);

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(
                parameters).WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(root)
                .WithMaxIndex(3).Build());
            Assert.AreEqual("maxIndex set but not reflected in state", e.Message);

            XmssPrivateKeyParameters key = new XmssPrivateKeyParameters.Builder(parameters).WithSecretKeySeed(seed)
                .WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(root).WithMaxIndex((1 << Height) - 1).Build();
            Assert.AreEqual(1 << Height, key.GetUsagesRemaining());
        }

        /// <summary>As <see cref="MaxIndexNotReflectedInStateRejected"/>, for the XMSS^MT builder.</summary>
        [Test]
        public void MTMaxIndexNotReflectedInStateRejected()
        {
            XmssMTParameters parameters = XmssMTParams();
            byte[] seed = new byte[parameters.TreeDigestSize];
            byte[] root = MTRootOf(parameters, seed, seed);

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssMTPrivateKeyParameters.Builder(
                parameters).WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(root)
                .WithMaxIndex(3).Build());
            Assert.AreEqual("maxIndex set but not reflected in state", e.Message);

            XmssMTPrivateKeyParameters key = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(root)
                .WithMaxIndex((1L << Height) - 1).Build();
            Assert.AreEqual(1L << Height, key.GetUsagesRemaining());
        }

        /// <summary>A state from the builder that is not at the builder's index is refused.</summary>
        [Test]
        public void StateAtAnotherIndexRejected()
        {
            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)GenerateXmss().Private;

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(
                key.Parameters).WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot()).WithBdsState(key.GetBdsState())
                .WithIndex(1).Build());
            Assert.AreEqual("BDS state has wrong index", e.Message);

            byte[] otherRoot = key.GetRoot();
            otherRoot[0] ^= 1;
            e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(key.Parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(otherRoot).WithBdsState(key.GetBdsState()).Build());
            Assert.AreEqual("BDS state root does not match the private key root", e.Message);
        }

        /// <summary>
        /// A key built from its seeds needs its root, and the root it is given must be the one the seeds compute: the
        /// root keys H_msg, so a key holding any other would spend one-time keys on signatures that do not verify.
        /// </summary>
        [Test]
        public void SeedRebuildRequiresTheComputedRoot()
        {
            XmssPrivateKeyParameters key = (XmssPrivateKeyParameters)GenerateXmss().Private;

            InvalidOperationException ie = Assert.Throws<InvalidOperationException>(() =>
                new XmssPrivateKeyParameters.Builder(key.Parameters).WithSecretKeySeed(key.GetSecretKeySeed())
                    .WithSecretKeyPrf(key.GetSecretKeyPrf()).WithPublicSeed(key.GetPublicSeed()).WithIndex(1).Build());
            Assert.AreEqual("root is null", ie.Message);

            byte[] otherRoot = key.GetRoot();
            otherRoot[0] ^= 1;
            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(
                key.Parameters).WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(otherRoot).WithIndex(1).Build());
            Assert.AreEqual("BDS state root does not match the private key root", e.Message);

            XmssPrivateKeyParameters rebuilt = new XmssPrivateKeyParameters.Builder(key.Parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot()).WithIndex(1).Build();
            Assert.AreEqual(1, rebuilt.Index);
        }

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="SeedRebuildRequiresTheComputedRoot"/>, at index 0 as well: a key
        /// rebuilt there holds the top layer key generation makes, so its root is compared as it is anywhere else.
        /// </summary>
        [Test]
        public void MTSeedRebuildRequiresTheComputedRoot()
        {
            XmssMTPrivateKeyParameters key = (XmssMTPrivateKeyParameters)GenerateXmssMT().Private;
            byte[] otherRoot = key.GetRoot();
            otherRoot[0] ^= 1;

            foreach (long index in new long[]{ 0L, 1L })
            {
                InvalidOperationException ie = Assert.Throws<InvalidOperationException>(() =>
                    new XmssMTPrivateKeyParameters.Builder(key.Parameters).WithSecretKeySeed(key.GetSecretKeySeed())
                        .WithSecretKeyPrf(key.GetSecretKeyPrf()).WithPublicSeed(key.GetPublicSeed())
                        .WithIndex(index).Build(), "index " + index);
                Assert.AreEqual("root is null", ie.Message);

                ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssMTPrivateKeyParameters.Builder(
                    key.Parameters).WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                    .WithPublicSeed(key.GetPublicSeed()).WithRoot(otherRoot).WithIndex(index).Build(),
                    "index " + index);
                Assert.AreEqual("BDS state root does not match the private key root", e.Message);
            }
        }

        /// <summary>
        /// A key rebuilt from its seeds at index 0 is the key key generation made, and signs. bc-java rebuilds an
        /// empty state map there and refuses to sign from it as not initialized.
        /// </summary>
        [Test]
        public void MTRebuildAtIndexZeroSigns()
        {
            AsymmetricCipherKeyPair kp = GenerateXmssMT();
            XmssMTPrivateKeyParameters key = (XmssMTPrivateKeyParameters)kp.Private;

            XmssMTPrivateKeyParameters rebuilt = new XmssMTPrivateKeyParameters.Builder(key.Parameters)
                .WithSecretKeySeed(key.GetSecretKeySeed()).WithSecretKeyPrf(key.GetSecretKeyPrf())
                .WithPublicSeed(key.GetPublicSeed()).WithRoot(key.GetRoot()).WithIndex(0L).Build();

            Assert.AreEqual(key, rebuilt);
            Assert.IsTrue(Arrays.AreEqual(key.GetEncoded(), rebuilt.GetEncoded()));

            byte[] message = new byte[]{ 1, 2, 3 };
            byte[] signature = XmssEngine.GenerateMTSignature(rebuilt, message);
            Assert.AreEqual(1L, rebuilt.Index);
            Assert.IsTrue(XmssEngine.VerifyMTSignature((XmssMTPublicKeyParameters)kp.Public, message, signature));
        }

        private static XmssPrivateKeyParameters RecoverXmssAt(XmssParameters parameters, byte[] seed, int index)
        {
            return new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed)
                .WithIndex(index).Build();
        }

        private static XmssMTPrivateKeyParameters RecoverXmssMTAt(XmssMTParameters parameters, byte[] seed,
            long index)
        {
            return new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed)
                .WithIndex(index).Build();
        }

        private static AsymmetricCipherKeyPair GenerateXmssMT()
        {
            XmssMTKeyPairGenerator gen = new XmssMTKeyPairGenerator();
            gen.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), XmssMTParams()));
            return gen.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateXmss()
        {
            XmssKeyPairGenerator gen = new XmssKeyPairGenerator();
            gen.Init(new XmssKeyGenerationParameters(new SecureRandom(), XmssParams()));
            return gen.GenerateKeyPair();
        }
    }
}
