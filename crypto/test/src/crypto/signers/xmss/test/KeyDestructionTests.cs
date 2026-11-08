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
    /// The XMSS^MT method arrives with the XMSS^MT keys and signer. The methods after <see cref="TestXmssDestroy"/>
    /// assert what is wiped: on Destroy(), and in the traversal states a key replaces as it moves on.
    /// </remarks>
    [TestFixture]
    public class KeyDestructionTests
    {
        private const int Height = 4;
        private static readonly byte[] Msg = new byte[]{ 1, 2, 3, 4 };

        private static AsymmetricCipherKeyPair XmssKeyPair()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(Height, new Sha256Digest())));

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
