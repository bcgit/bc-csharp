using System;
using System.Reflection;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>Destroy() on the key parameter classes (github #2432).</summary>
    /// <remarks>
    /// The methods after <see cref="TestXmssMTDestroy"/> assert what is wiped, for both families: on Destroy(), and in
    /// the traversal states and state maps a key replaces as it moves on.
    /// </remarks>
    [TestFixture]
    public class KeyDestructionTests
    {
        private const int Height = 4;
        private const int Layers = 2;
        private static readonly byte[] Msg = new byte[]{ 1, 2, 3, 4 };

        private static AsymmetricCipherKeyPair XmssKeyPair()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(Height, new Sha256Digest())));

            return kpg.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair XmssMTKeyPair()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(Height, Layers, new Sha256Digest())));

            return kpg.GenerateKeyPair();
        }

        private static byte[] Sign(XmssSigner signer, XmssPrivateKeyParameters key)
        {
            signer.Init(true, key);
            signer.BlockUpdate(Msg, 0, Msg.Length);

            return signer.GenerateSignature();
        }

        private static bool Verify(XmssSigner signer, XmssPublicKeyParameters key, byte[] sig)
        {
            signer.Init(false, key);
            signer.BlockUpdate(Msg, 0, Msg.Length);

            return signer.VerifySignature(sig);
        }

        private static byte[] Sign(XmssMTSigner signer, XmssMTPrivateKeyParameters key)
        {
            signer.Init(true, key);
            signer.BlockUpdate(Msg, 0, Msg.Length);

            return signer.GenerateSignature();
        }

        private static bool Verify(XmssMTSigner signer, XmssMTPublicKeyParameters key, byte[] sig)
        {
            signer.Init(false, key);
            signer.BlockUpdate(Msg, 0, Msg.Length);

            return signer.VerifySignature(sig);
        }

        [Test]
        public void TestXmssDestroy()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            byte[] sig = Sign(new XmssSigner(), priv);

            // split off before destruction: it holds its own copies of the seeds
            XmssPrivateKeyParameters shard = priv.ExtractKeyShard(2);

            int index = priv.Index;
            byte[] publicSeed = priv.GetPublicSeed();
            byte[] root = priv.GetRoot();

            Assert.IsFalse(priv.IsDestroyed);
            Assert.IsNotNull(priv.GetSecretKeySeed());

            priv.Destroy();

            Assert.IsTrue(priv.IsDestroyed);

            CheckThrowsDestroyed("GetSecretKeySeed", key => key.GetSecretKeySeed(), priv);
            CheckThrowsDestroyed("GetSecretKeyPrf", key => key.GetSecretKeyPrf(), priv);
            CheckThrowsDestroyed("GetEncoded", key => key.GetEncoded(), priv);
            CheckThrowsDestroyed("GetNextKey", key => key.GetNextKey(), priv);
            CheckThrowsDestroyed("ExtractKeyShard", key => key.ExtractKeyShard(1), priv);
            CheckThrowsDestroyed("GenerateSignature", key => Sign(new XmssSigner(), key), priv);

            // the refusal is ahead of the try whose finally rolls the key, so nothing moved
            Assert.AreEqual(index, priv.Index, "a refused signature advanced the index");
            Assert.IsFalse(priv.GetBdsState().IsUsed, "a refused signature marked the traversal state used");

            // the public side is not secret and is kept
            Assert.IsTrue(Arrays.AreEqual(publicSeed, priv.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(root, priv.GetRoot()));
            Assert.IsNotNull(priv.Parameters);

            Assert.IsTrue(Verify(new XmssSigner(), pub, sig), "a signature made before Destroy() no longer verifies");

            Assert.IsFalse(shard.IsDestroyed);
            Assert.IsTrue(Verify(new XmssSigner(), pub, Sign(new XmssSigner(), shard)),
                "the shard stopped signing when its source was destroyed");

            // idempotent
            priv.Destroy();
            Assert.IsTrue(priv.IsDestroyed);
        }

        [Test]
        public void TestXmssMTDestroy()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pub = (XmssMTPublicKeyParameters)kp.Public;

            byte[] sig = Sign(new XmssMTSigner(), priv);

            XmssMTPrivateKeyParameters shard = priv.ExtractKeyShard(2);

            long index = priv.Index;
            byte[] publicSeed = priv.GetPublicSeed();
            byte[] root = priv.GetRoot();

            Assert.IsFalse(priv.IsDestroyed);

            priv.Destroy();

            Assert.IsTrue(priv.IsDestroyed);

            CheckThrowsDestroyed("GetSecretKeySeed", () => priv.GetSecretKeySeed());
            CheckThrowsDestroyed("GetSecretKeyPrf", () => priv.GetSecretKeyPrf());
            CheckThrowsDestroyed("GetEncoded", () => priv.GetEncoded());
            CheckThrowsDestroyed("GetNextKey", () => priv.GetNextKey());
            CheckThrowsDestroyed("ExtractKeyShard", () => priv.ExtractKeyShard(1));
            CheckThrowsDestroyed("GenerateSignature", () => Sign(new XmssMTSigner(), priv));

            Assert.AreEqual(index, priv.Index, "a refused signature advanced the index");
            Assert.IsFalse(priv.GetBdsState().IsUsed, "a refused signature marked the traversal state used");

            Assert.IsTrue(Arrays.AreEqual(publicSeed, priv.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(root, priv.GetRoot()));
            Assert.IsNotNull(priv.Parameters);

            Assert.IsTrue(Verify(new XmssMTSigner(), pub, sig), "a signature made before Destroy() no longer verifies");

            Assert.IsFalse(shard.IsDestroyed);
            Assert.IsTrue(Verify(new XmssMTSigner(), pub, Sign(new XmssMTSigner(), shard)),
                "the shard stopped signing when its source was destroyed");

            priv.Destroy();
            Assert.IsTrue(priv.IsDestroyed);
        }

        /// <summary>
        /// After Destroy() the encoding is refused, the secret arrays the key holds and the WOTS+ secret its
        /// traversal state retains are zeroed, and copies handed out before are the caller's and untouched.
        /// RollKey() is refused too, and leaves the index where it was.
        /// </summary>
        [Test]
        public void Destroy_ThenGetEncoded_Throws()
        {
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)XmssKeyPair().Private;
            // a roll leaves the traversal state holding the WOTS+ secret key of the leaf it last processed
            priv.RollKey();

            byte[] seedBefore = priv.GetSecretKeySeed();
            byte[] prfBefore = priv.GetSecretKeyPrf();
            byte[] seedCopy = Arrays.Clone(seedBefore);
            byte[] prfCopy = Arrays.Clone(prfBefore);
            Assert.IsFalse(Arrays.AreAllZeroes(seedBefore, 0, seedBefore.Length));
            Assert.IsFalse(Arrays.AreAllZeroes(prfBefore, 0, prfBefore.Length));
            Assert.IsFalse(IsZero(BdsWotsSecret(priv.GetBdsState())), "no WOTS+ secret retained to wipe");

            priv.Destroy();

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => priv.GetEncoded());
            Assert.AreEqual("key destroyed", e.Message);
            e = Assert.Throws<InvalidOperationException>(() => priv.RollKey());
            Assert.AreEqual("key destroyed", e.Message);
            Assert.AreEqual(1, priv.Index);

            Assert.IsTrue(Arrays.AreEqual(seedCopy, seedBefore), "a copy handed out before Destroy() was wiped");
            Assert.IsTrue(Arrays.AreEqual(prfCopy, prfBefore), "a copy handed out before Destroy() was wiped");
            Assert.IsTrue(IsZero(priv.LiveSecretKeySeed), "secret key seed not wiped");
            Assert.IsTrue(IsZero(priv.LiveSecretKeyPrf), "secret key PRF not wiped");
            Assert.IsTrue(IsZero(BdsWotsSecret(priv.GetBdsState())), "traversal state WOTS+ secret not wiped");
        }

        /// <summary>
        /// A traversal state a key replaces as it moves on is wiped: it can hold the WOTS+ secret key of a leaf the
        /// key has yet to sign with.
        /// </summary>
        [Test]
        public void RollKey_WipesTheReplacedState()
        {
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)XmssKeyPair().Private;
            priv.RollKey();

            Bds replaced = priv.GetBdsState();
            Assert.IsFalse(IsZero(BdsWotsSecret(replaced)), "no WOTS+ secret retained to wipe");

            priv.RollKey();

            Assert.AreNotSame(replaced, priv.GetBdsState());
            Assert.IsTrue(IsZero(BdsWotsSecret(replaced)), "the replaced state's WOTS+ secret was not wiped");

            // and the key goes on signing
            Assert.AreEqual(2, XmssHarnessTests.IndexOf(Sign(new XmssSigner(), priv)));
        }

        /// <summary>
        /// As <see cref="RollKey_WipesTheReplacedState"/>, for the states ExtractKeyShard() replaces.
        /// </summary>
        [Test]
        public void ExtractKeyShard_WipesTheReplacedStates()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;
            priv.RollKey();

            Bds replaced = priv.GetBdsState();
            Assert.IsFalse(IsZero(BdsWotsSecret(replaced)), "no WOTS+ secret retained to wipe");

            XmssPrivateKeyParameters shard = priv.ExtractKeyShard(3);

            Assert.IsTrue(IsZero(BdsWotsSecret(replaced)), "the replaced state's WOTS+ secret was not wiped");

            // neither the shard, whose state was copied from the one wiped, nor the key is the worse for it
            Assert.IsTrue(Verify(new XmssSigner(), pub, Sign(new XmssSigner(), shard)));
            Assert.AreEqual(4, XmssHarnessTests.IndexOf(Sign(new XmssSigner(), priv)));

            // the branch that hands out the whole of what is left
            Bds last = priv.GetBdsState();
            Assert.IsFalse(IsZero(BdsWotsSecret(last)), "no WOTS+ secret retained to wipe");

            XmssPrivateKeyParameters rest = priv.ExtractKeyShard((int)priv.GetUsagesRemaining());

            Assert.IsTrue(IsZero(BdsWotsSecret(last)), "the replaced state's WOTS+ secret was not wiped");
            Assert.AreEqual(0, priv.GetUsagesRemaining());
            Assert.IsTrue(Verify(new XmssSigner(), pub, Sign(new XmssSigner(), rest)));
        }

        /// <summary>
        /// Two keys built from one builder share no secret array and no traversal state, so destroying one leaves the
        /// other signing verifiably.
        /// </summary>
        [Test]
        public void TwoKeysFromOneBuilder_ShareNoSecrets()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters source = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            XmssPrivateKeyParameters.Builder builder = new XmssPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot())
                .WithBdsState(source.GetBdsState());

            XmssPrivateKeyParameters first = builder.Build();
            XmssPrivateKeyParameters second = builder.Build();

            Assert.AreNotSame(first.LiveSecretKeySeed, second.LiveSecretKeySeed);
            Assert.AreNotSame(first.LiveSecretKeyPrf, second.LiveSecretKeyPrf);
            Assert.AreNotSame(first.GetBdsState(), second.GetBdsState());

            first.Destroy();

            Assert.IsFalse(IsZero(second.LiveSecretKeySeed), "destroying one key wiped the other's seed");
            Assert.IsFalse(IsZero(second.LiveSecretKeyPrf), "destroying one key wiped the other's PRF key");
            Assert.IsTrue(Verify(new XmssSigner(), pub, Sign(new XmssSigner(), second)),
                "the surviving key no longer signs verifiably");

            // and the same for keys built from seeds alone, whose state each builds for itself
            XmssPrivateKeyParameters.Builder seeds = new XmssPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot()).WithIndex(3);
            XmssPrivateKeyParameters third = seeds.Build();
            XmssPrivateKeyParameters fourth = seeds.Build();

            third.Destroy();

            Assert.IsFalse(IsZero(fourth.LiveSecretKeySeed), "destroying one key wiped the other's seed");
            Assert.IsTrue(Verify(new XmssSigner(), pub, Sign(new XmssSigner(), fourth)),
                "the surviving key no longer signs verifiably");

            // a state built for one key is adopted by the first Build() alone; a second gets a copy
            Bds owned = source.GetBdsState().WithMaxIndex(source.GetBdsState().MaxIndex,
                source.Parameters.TreeDigestOid, source.Parameters.TreeDigestSize);
            XmssPrivateKeyParameters.Builder adopting = new XmssPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot()).WithOwnedBdsState(owned);
            XmssPrivateKeyParameters fifth = adopting.Build();
            XmssPrivateKeyParameters sixth = adopting.Build();

            Assert.AreSame(owned, fifth.GetBdsState());
            Assert.AreNotSame(owned, sixth.GetBdsState());
        }

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="TwoKeysFromOneBuilder_ShareNoSecrets"/>: two keys built from one
        /// builder share no secret array, no state map and no layer state, so destroying one leaves the other
        /// signing verifiably.
        /// </summary>
        [Test]
        public void MTTwoKeysFromOneBuilder_ShareNoSecrets()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTPrivateKeyParameters source = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pub = (XmssMTPublicKeyParameters)kp.Public;

            // past the first signature, so the bottom layer is built and both layers are there to be shared
            Sign(new XmssMTSigner(), source);

            XmssMTPrivateKeyParameters.Builder builder = new XmssMTPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot()).WithIndex(source.Index)
                .WithBdsState(source.GetBdsState());

            XmssMTPrivateKeyParameters first = builder.Build();
            XmssMTPrivateKeyParameters second = builder.Build();

            Assert.AreNotSame(first.LiveSecretKeySeed, second.LiveSecretKeySeed);
            Assert.AreNotSame(first.LiveSecretKeyPrf, second.LiveSecretKeyPrf);
            Assert.AreNotSame(first.GetBdsState(), second.GetBdsState());
            for (int layer = 0; layer != Layers; layer++)
            {
                Assert.IsNotNull(first.GetBdsState().Get(layer), "layer " + layer);
                Assert.AreNotSame(first.GetBdsState().Get(layer), second.GetBdsState().Get(layer), "layer " + layer);
            }

            first.Destroy();

            Assert.IsFalse(IsZero(second.LiveSecretKeySeed), "destroying one key wiped the other's seed");
            Assert.IsFalse(IsZero(second.LiveSecretKeyPrf), "destroying one key wiped the other's PRF key");
            Assert.IsTrue(Verify(new XmssMTSigner(), pub, Sign(new XmssMTSigner(), second)),
                "the surviving key no longer signs verifiably");

            // and the same for keys built from seeds alone, whose state each builds for itself
            XmssMTPrivateKeyParameters.Builder seeds = new XmssMTPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot()).WithIndex(3);
            XmssMTPrivateKeyParameters third = seeds.Build();
            XmssMTPrivateKeyParameters fourth = seeds.Build();

            Assert.AreNotSame(third.LiveSecretKeySeed, fourth.LiveSecretKeySeed);

            third.Destroy();

            Assert.IsFalse(IsZero(fourth.LiveSecretKeySeed), "destroying one key wiped the other's seed");
            Assert.IsTrue(Verify(new XmssMTSigner(), pub, Sign(new XmssMTSigner(), fourth)),
                "the surviving key no longer signs verifiably");

            // a state map built for one key is adopted by the first Build() alone; a second gets a copy
            BdsStateMap owned = new BdsStateMap(source.GetBdsState(), source.GetBdsState().MaxIndex);
            XmssMTPrivateKeyParameters.Builder adopting = new XmssMTPrivateKeyParameters.Builder(source.Parameters)
                .WithSecretKeySeed(source.GetSecretKeySeed()).WithSecretKeyPrf(source.GetSecretKeyPrf())
                .WithPublicSeed(source.GetPublicSeed()).WithRoot(source.GetRoot()).WithIndex(source.Index)
                .WithOwnedBdsState(owned);
            XmssMTPrivateKeyParameters fifth = adopting.Build();
            XmssMTPrivateKeyParameters sixth = adopting.Build();

            Assert.AreSame(owned, fifth.GetBdsState());
            Assert.AreNotSame(owned, sixth.GetBdsState());
            Assert.AreNotSame(owned.Get(0), sixth.GetBdsState().Get(0));
        }

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="Destroy_ThenGetEncoded_Throws"/>: the seeds and the WOTS+ secret
        /// every layer's state retains are zeroed, every operation that reads or moves the key is refused, and a
        /// signature is refused before the index moves.
        /// </summary>
        [Test]
        public void MTDestroy_ThenGetEncoded_Throws()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;
            byte[] sig = XmssEngine.GenerateMTSignature(priv, Msg);
            XmssMTPrivateKeyParameters shard = priv.ExtractKeyShard(2);

            byte[] seedCopy = priv.GetSecretKeySeed();
            Assert.IsTrue(AnyLayerHoldsASecret(priv.GetBdsState()), "no WOTS+ secret retained to wipe");

            long index = priv.Index;

            priv.Destroy();

            Assert.IsTrue(priv.IsDestroyed);
            CheckThrowsDestroyed("GetSecretKeySeed", () => priv.GetSecretKeySeed());
            CheckThrowsDestroyed("GetSecretKeyPrf", () => priv.GetSecretKeyPrf());
            CheckThrowsDestroyed("GetEncoded", () => priv.GetEncoded());
            CheckThrowsDestroyed("RollKey", () => priv.RollKey());
            CheckThrowsDestroyed("GetNextKey", () => priv.GetNextKey());
            CheckThrowsDestroyed("ExtractKeyShard", () => priv.ExtractKeyShard(1));
            CheckThrowsDestroyed("GenerateMTSignature", () => XmssEngine.GenerateMTSignature(priv, Msg));

            Assert.AreEqual(index, priv.Index, "a refused operation advanced the index");
            Assert.IsTrue(IsZero(priv.LiveSecretKeySeed), "secret key seed not wiped");
            Assert.IsTrue(IsZero(priv.LiveSecretKeyPrf), "secret key PRF not wiped");
            Assert.IsFalse(AnyLayerHoldsASecret(priv.GetBdsState()), "a layer's WOTS+ secret was not wiped");
            Assert.IsFalse(IsZero(seedCopy), "a copy handed out before Destroy() was wiped");

            XmssMTPublicKeyParameters pub = (XmssMTPublicKeyParameters)kp.Public;
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, sig));
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, XmssEngine.GenerateMTSignature(shard, Msg)),
                "the shard stopped signing when its source was destroyed");

            priv.Destroy();
            Assert.IsTrue(priv.IsDestroyed);
        }

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="RollKey_WipesTheReplacedState"/>: the state map a key replaces as
        /// it rolls is wiped, every layer of it, once the new one is in place.
        /// </summary>
        [Test]
        public void MTRollKey_WipesTheReplacedStateMap()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;
            priv.RollKey();

            BdsStateMap replaced = priv.GetBdsState();
            Assert.IsTrue(AnyLayerHoldsASecret(replaced), "no WOTS+ secret retained to wipe");

            priv.RollKey();

            Assert.AreNotSame(replaced, priv.GetBdsState());
            Assert.IsFalse(AnyLayerHoldsASecret(replaced), "the replaced state map's WOTS+ secrets were not wiped");

            // and the key goes on signing, across the subtree boundary at index 4
            for (int i = 2; i != 6; i++)
            {
                Assert.IsTrue(XmssEngine.VerifyMTSignature((XmssMTPublicKeyParameters)kp.Public, Msg,
                    XmssEngine.GenerateMTSignature(priv, Msg)), "index " + i);
            }
        }

        /// <summary>
        /// The state maps ExtractKeyShard() and GetNextKey() replace are wiped, and neither the shard, whose map was
        /// copied from one of them, nor the key is the worse for it.
        /// </summary>
        [Test]
        public void MTExtractKeyShard_WipesTheReplacedStateMaps()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pub = (XmssMTPublicKeyParameters)kp.Public;
            priv.RollKey();

            BdsStateMap replaced = priv.GetBdsState();
            Assert.IsTrue(AnyLayerHoldsASecret(replaced), "no WOTS+ secret retained to wipe");

            XmssMTPrivateKeyParameters shard = priv.ExtractKeyShard(3);

            Assert.IsFalse(AnyLayerHoldsASecret(replaced), "the replaced state map's WOTS+ secrets were not wiped");
            Assert.AreEqual(4L, priv.Index);
            for (int i = 0; i != 3; i++)
            {
                Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, XmssEngine.GenerateMTSignature(shard, Msg)));
            }
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, XmssEngine.GenerateMTSignature(priv, Msg)));

            // GetNextKey() is a shard of one
            BdsStateMap last = priv.GetBdsState();
            Assert.IsTrue(AnyLayerHoldsASecret(last), "no WOTS+ secret retained to wipe");

            XmssMTPrivateKeyParameters next = priv.GetNextKey();

            Assert.IsFalse(AnyLayerHoldsASecret(last), "the replaced state map's WOTS+ secrets were not wiped");
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, XmssEngine.GenerateMTSignature(next, Msg)));
            Assert.AreEqual(0, next.GetUsagesRemaining());

            // and the branch that hands out the whole of what is left, ending on the exhausted placeholder
            XmssMTPrivateKeyParameters rest = priv.ExtractKeyShard((int)priv.GetUsagesRemaining());

            Assert.AreEqual(0, priv.GetUsagesRemaining());
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, Msg, XmssEngine.GenerateMTSignature(rest, Msg)));
        }

        /// <summary>
        /// A layer state a state map replaces as it advances - and the one replaced when a layer is rebuilt for a
        /// new subtree - is wiped too: it can hold the WOTS+ secret key of a leaf yet to sign with.
        /// </summary>
        [Test]
        public void MTStateMapWipesTheLayerStatesItReplaces()
        {
            // layer trees of height 4, so a layer state can be advanced more than once
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(8, 2, new Sha256Digest())));
            XmssMTPrivateKeyParameters priv = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            XmssParameters xmssParams = priv.Parameters.XmssParameters;
            byte[] publicSeed = priv.GetPublicSeed();
            byte[] secretKeySeed = priv.GetSecretKeySeed();
            priv.RollKey();
            priv.RollKey();

            // a map of its own, so nothing the key holds is touched; the step from index 2 to 3 is a leaf, which
            // leaves that leaf's WOTS+ secret key in the new layer zero state
            BdsStateMap map = XmssEngine.GetNextBdsStateMap(priv.GetBdsState(), priv.Parameters, priv.Index,
                publicSeed, secretKeySeed);

            Bds layerZero = map.Get(0);
            Assert.AreEqual(3, layerZero.Index);
            Assert.IsFalse(IsZero(BdsWotsSecret(layerZero)), "no WOTS+ secret retained to wipe");

            map.Update(0, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0));

            Assert.AreNotSame(layerZero, map.Get(0));
            Assert.AreEqual(4, map.Get(0).Index);
            Assert.IsTrue(IsZero(BdsWotsSecret(layerZero)), "the layer state Update() replaced was not wiped");

            // a layer rebuilt for a new subtree: building a state walks its whole tree, leaving the last leaf's
            // WOTS+ secret key behind
            Bds built = new Bds(xmssParams, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 1L, 0));
            Assert.IsFalse(IsZero(BdsWotsSecret(built)), "no WOTS+ secret retained to wipe");

            map.Put(0, built);
            map.Put(0, new Bds(xmssParams, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 2L, 0)));

            Assert.IsTrue(IsZero(BdsWotsSecret(built)), "the layer state Put() replaced was not wiped");

            // putting back the state already there is not a replacement, and wipes nothing
            Bds current = map.Get(0);
            map.Put(0, current);
            Assert.IsFalse(IsZero(BdsWotsSecret(current)), "a state put back in its own place was wiped");
        }

        private static bool AnyLayerHoldsASecret(BdsStateMap map)
        {
            for (int layer = 0; layer != Layers; layer++)
            {
                Bds state = map.Get(layer);
                if (state != null && !IsZero(BdsWotsSecret(state)))
                    return true;
            }
            return false;
        }

        private static void CheckThrowsDestroyed(string name, Action op)
        {
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => op(),
                name + " did not refuse a destroyed key");
            Assert.AreEqual("key destroyed", e.Message, name);
        }

        private static bool IsZero(byte[] data) => Arrays.AreAllZeroes(data, 0, data.Length);

        /// <summary>
        /// The WOTS+ secret key a traversal state's hash-function instance imported last. Read by reflection: it is
        /// private two levels down, and nothing outside a test has a reason to reach it.
        /// </summary>
        internal static byte[] BdsWotsSecret(Bds state)
        {
            const BindingFlags Flags = BindingFlags.Instance | BindingFlags.NonPublic;
            object wotsPlus = typeof(Bds).GetField("m_wotsPlus", Flags).GetValue(state);
            return (byte[])typeof(WotsPlus).GetField("m_secretKeySeed", Flags).GetValue(wotsPlus);
        }

        private static void CheckThrowsDestroyed(string name, Action<XmssPrivateKeyParameters> op,
            XmssPrivateKeyParameters key)
        {
            try
            {
                op(key);
                Assert.Fail(name + " did not refuse a destroyed key");
            }
            catch (InvalidOperationException e)
            {
                Assert.AreEqual("key destroyed", e.Message, name);
            }
        }
    }
}
