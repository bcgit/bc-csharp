using System;
using System.Diagnostics;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>The XMSS / XMSS^MT key parameter builders.</summary>
    /// <remarks>
    /// The Java tests are written in XMSS / XMSS^MT pairs. The XMSS half of each is here; the XMSS^MT halves, and
    /// the two XMSS^MT methods, arrive with the XMSS^MT keys. testSingleUseShardCoversOneSignature and
    /// testRecoveryAtTheExhaustedIndex sign through XmssSigner and arrive with it.
    /// </remarks>
    [TestFixture]
    public class KeyParametersBuilderTests
    {
        private const int Height = 4;

        private static XmssParameters XmssParams() => new XmssParameters(Height, new Sha256Digest());

        /// <summary>The root the seeds compute, which a key built from them must declare.</summary>
        private static byte[] RootOf(XmssParameters parameters, byte[] secretKeySeed, byte[] publicSeed) =>
            new Bds(parameters, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0)).Root.GetValue();

        /// <summary>A null parameter set is rejected where it is passed. All builders share the wording.</summary>
        [Test]
        public void TestNullParametersRejectedByBuilder()
        {
            ArgumentNullException e = Assert.Throws<ArgumentNullException>(
                () => new XmssPrivateKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);

            e = Assert.Throws<ArgumentNullException>(() => new XmssPublicKeyParameters.Builder(null));
            StringAssert.StartsWith("params == null", e.Message);

            // XMSS^MT half: arrives with the XMSS^MT keys.
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

            e = Assert.Throws<ArgumentException>(() => new XmssPublicKeyParameters.Builder(XmssParams())
                .WithRoot(shortSeed).WithPublicSeed(seed).Build());
            Assert.AreEqual("size of root needs to be equal to size of digest", e.Message);

            e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(XmssParams())
                .WithSecretKeySeed(shortSeed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed).Build());
            Assert.AreEqual("size of secretKeySeed needs to be equal to size of digest", e.Message);

            // XMSS^MT half: arrives with the XMSS^MT keys.
        }

        /// <summary>The private key builder will not hand back a key whose seeds it had to invent.</summary>
        [Test]
        public void TestPrivateKeyWithoutSeedsRejected()
        {
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => new XmssPrivateKeyParameters.Builder(XmssParams()).Build());
            Assert.AreEqual("publicSeed or secretKeySeed is null", e.Message);

            // XMSS^MT half: arrives with the XMSS^MT keys.
        }

        /// <summary>The seed check is a disjunction - an imported private key carries its own seeds.</summary>
        [Test]
        public void TestPrivateKeyImportStillAccepted()
        {
            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(XmssParams())
                .WithPrivateKey(xmss.GetEncoded()).Build();
            Assert.IsTrue(Arrays.AreEqual(xmss.GetEncoded(), recovered.GetEncoded()));

            // XMSS^MT half: arrives with the XMSS^MT keys.
        }

        /// <summary>A generated key can be used 2^h times.</summary>
        [Test]
        public void TestGeneratedKeysReportFullUsageCount()
        {
            long expected = 1L << Height;

            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            Assert.AreEqual(expected, xmss.GetUsagesRemaining());
            Assert.AreEqual(expected - 1, xmss.GetBdsState().MaxIndex);

            // XMSS^MT half: arrives with the XMSS^MT keys.
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
        /// 2^h, the index of a key with every leaf spent, rebuilds to the state RollKey() leaves there. The Java
        /// method goes on to sign through XmssSigner; that part arrives with the signer.
        /// </summary>
        [Test]
        public void RecoveryAtTheExhaustedIndex_Key()
        {
            XmssParameters parameters = XmssParams();
            byte[] seed = new byte[parameters.TreeDigestSize];

            XmssPrivateKeyParameters spent = RecoverXmssAt(parameters, seed, 1 << Height);

            Assert.AreEqual(1 << Height, spent.Index);
            Assert.AreEqual(0, spent.GetUsagesRemaining());
            Assert.AreEqual((1 << Height) - 1, spent.GetBdsState().MaxIndex);
        }

        /// <summary>
        /// GetNextKey() takes a single-use shard: index 0 alone, maximum index 0, and the key it came from moves to
        /// index 1. The Java method goes on to sign through XmssSigner; that part arrives with the signer.
        /// </summary>
        [Test]
        public void SingleUseShardCoversOneIndex_Key()
        {
            XmssPrivateKeyParameters xmss = (XmssPrivateKeyParameters)GenerateXmss().Private;
            XmssPrivateKeyParameters xmssShard = xmss.GetNextKey();

            Assert.AreEqual(0, xmssShard.Index);
            Assert.AreEqual(0, xmssShard.GetBdsState().MaxIndex);
            Assert.AreEqual(1, xmssShard.GetUsagesRemaining());
            Assert.AreEqual(1, xmss.Index);
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

        private static XmssPrivateKeyParameters RecoverXmssAt(XmssParameters parameters, byte[] seed, int index)
        {
            return new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(seed).WithSecretKeyPrf(seed).WithPublicSeed(seed).WithRoot(seed)
                .WithIndex(index).Build();
        }

        private static AsymmetricCipherKeyPair GenerateXmss()
        {
            XmssKeyPairGenerator gen = new XmssKeyPairGenerator();
            gen.Init(new XmssKeyGenerationParameters(new SecureRandom(), XmssParams()));
            return gen.GenerateKeyPair();
        }
    }
}
