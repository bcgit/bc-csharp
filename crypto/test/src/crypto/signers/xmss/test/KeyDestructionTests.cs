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
    /// The Java methods sign and verify through XMSSSigner, which arrives in a later change. The XMSS method signs
    /// and verifies here through <see cref="XmssEngine"/>, which is all the signer does with a key; the XMSS^MT method
    /// arrives with the XMSS^MT keys.
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

        private static byte[] Sign(XmssPrivateKeyParameters key) => XmssEngine.GenerateSignature(key, Msg);

        private static bool Verify(XmssPublicKeyParameters key, byte[] sig) =>
            XmssEngine.VerifySignature(key, Msg, sig);

        [Test]
        public void TestXmssDestroy()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            byte[] sig = Sign(priv);

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
            CheckThrowsDestroyed("GenerateSignature", key => Sign(key), priv);

            // the refusal is ahead of the try whose finally rolls the key, so nothing moved
            Assert.AreEqual(index, priv.Index, "a refused signature advanced the index");
            Assert.IsFalse(priv.GetBdsState().IsUsed, "a refused signature marked the traversal state used");

            // the public side is not secret and is kept
            Assert.IsTrue(Arrays.AreEqual(publicSeed, priv.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(root, priv.GetRoot()));
            Assert.IsNotNull(priv.Parameters);

            Assert.IsTrue(Verify(pub, sig), "a signature made before Destroy() no longer verifies");

            Assert.IsFalse(shard.IsDestroyed);
            Assert.IsTrue(Verify(pub, Sign(shard)), "the shard stopped signing when its source was destroyed");

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

        private static bool IsZero(byte[] data) => Arrays.AreAllZeroes(data, 0, data.Length);

        /// <summary>
        /// The WOTS+ secret key a traversal state's hash-function instance imported last. Read by reflection: it is
        /// private two levels down, and nothing outside a test has a reason to reach it.
        /// </summary>
        private static byte[] BdsWotsSecret(Bds state)
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
