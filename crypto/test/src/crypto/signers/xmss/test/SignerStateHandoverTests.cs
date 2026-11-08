using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// <see cref="XmssSigner.GetUpdatedPrivateKey"/> is how a caller collects the advanced state it is obliged to
    /// persist, so it is reached in situations where there is no state to collect: a signer that was never
    /// initialised for signing, one initialised only for verification, and one whose key a previous call has already
    /// taken. All three report an absent key the same way.
    /// </summary>
    /// <remarks>
    /// The XMSS half of each Java method; the XMSS^MT halves arrive with the XMSS^MT signer.
    /// </remarks>
    [TestFixture]
    public class SignerStateHandoverTests
    {
        private const int Height = 4;

        private static AsymmetricCipherKeyPair XmssKeyPair(XmssParameters parameters)
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            return kpg.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair XmssKeyPair() => XmssKeyPair(new XmssParameters(Height,
            new Sha256Digest()));

        /// <summary>
        /// Having signed, the first call hands the advanced key over and the second reports that there is nothing
        /// left to hand over.
        /// </summary>
        [Test]
        public void TestKeyCollectedOnlyOnceAfterSigning()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);
            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);
            signer.GenerateSignature();

            Assert.AreSame(kp.Private, signer.GetUpdatedPrivateKey());
            Assert.IsNull(signer.GetUpdatedPrivateKey());
        }

        /// <summary>
        /// A signer with no signing key to give back says so, whether it was never initialised at all or initialised
        /// for verification.
        /// </summary>
        [Test]
        public void TestNoKeyToCollectReportedAsAbsent()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();

            Assert.IsNull(new XmssSigner().GetUpdatedPrivateKey());

            XmssSigner verifier = new XmssSigner();

            verifier.Init(false, kp.Public);
            Assert.IsNull(verifier.GetUpdatedPrivateKey());
        }

        /// <summary>
        /// Initialised but not yet used, the key stays with the caller and the signer keeps the shard covering the
        /// usage it has not spent.
        /// </summary>
        [Test]
        public void TestInitialisedButUnusedSignerHandsBackTheKeyItWasGiven()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);

            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreEqual((1 << Height) - 1, privKey.GetUsagesRemaining());
            Assert.AreEqual(1, signer.GetUsagesRemaining()); // the shard covers the one unspent usage
        }

        /// <summary>
        /// A signature the engine refuses must leave the signer where it was, because what
        /// <see cref="XmssSigner.GetUpdatedPrivateKey"/> does next turns on whether one was made. A traversal state
        /// that has already signed at its index is refused ahead of the roll; after the refusal the signer must hand
        /// its key over and still hold one, as if it had never been asked to sign.
        /// </summary>
        [Test]
        public void TestRefusedSignatureLeavesTheSignerHoldingItsKey()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssPrivateKeyParameters spender = (XmssPrivateKeyParameters)XmssKeyPair(parameters).Private;
            Bds spent = spender.GetBdsState();

            XmssEngine.GenerateSignature(spender, new byte[]{ 0x01 });

            XmssPrivateKeyParameters privKey = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(spender.GetSecretKeySeed()).WithSecretKeyPrf(spender.GetSecretKeyPrf())
                .WithPublicSeed(spender.GetPublicSeed()).WithRoot(spender.GetRoot())
                .WithBdsState(spent).Build();

            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);
            signer.BlockUpdate(new byte[]{ 0x02 }, 0, 1);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => signer.GenerateSignature(),
                "a state that has already signed must not sign again");
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);

            Assert.AreEqual(0, privKey.Index, "the refused signature must not have moved the key");
            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.IsNotNull(signer.GetUpdatedPrivateKey(), "the signer spent nothing, so it still holds a key");
        }

        /// <summary>
        /// Collected twice with no signature between, a signer hands back the same key both times rather than
        /// sharding off the one leaf it keeps for itself: a caller storing the latest collection would otherwise
        /// write a key with nothing remaining over a live one. The signer still holds its own leaf after both calls,
        /// and can still spend it.
        /// </summary>
        [Test]
        public void TestCollectingTwiceWithNoSignatureBetweenHandsBackTheSameKey()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);

            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreEqual((1 << Height) - 1, privKey.GetUsagesRemaining(),
                "the collected key keeps every usage the signer is not holding");
            Assert.AreEqual(1, signer.GetUsagesRemaining());

            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);
            Assert.IsNotNull(signer.GenerateSignature(), "the leaf the signer kept is still there to spend");
        }

        /// <summary>
        /// Collecting and then signing leaves nothing further to collect: the collection handed the caller every
        /// usage but the one the signer kept, the signature spent that one, and the spent shard adds nothing.
        /// </summary>
        [Test]
        public void TestCollectionAfterACollectionAndASignatureIsRefused()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);

            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreEqual((1 << Height) - 1, privKey.GetUsagesRemaining(),
                "the collection handed back everything but the usage the signer kept");

            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);
            signer.GenerateSignature();

            Assert.IsNull(signer.GetUpdatedPrivateKey(), "the spent shard was handed over rather than refused");
            Assert.IsNull(signer.GetUpdatedPrivateKey());
            Assert.AreEqual((1 << Height) - 1, privKey.GetUsagesRemaining(),
                "the collected key is untouched by the signature the shard made");
        }

        /// <summary>
        /// A signer given a key with nothing left to spend still has state its caller has to store. There is no next
        /// usage to leave behind, so the spent key itself is what comes back - twice over, since nothing was consumed
        /// handing it over.
        /// </summary>
        [Test]
        public void TestSpentKeyHandedBackRatherThanShardedAgain()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;

            privKey.ExtractKeyShard(1 << Height); // takes every usage the key had

            Assert.AreEqual(0, privKey.GetUsagesRemaining());

            XmssSigner signer = new XmssSigner();

            signer.Init(true, privKey);

            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            Assert.AreEqual(0, privKey.GetUsagesRemaining());
        }

        /// <summary>
        /// An argument that was never supplied is the caller's mistake, not a signature that failed to verify -
        /// bytes that will not decode are reported as false, but there are no bytes here.
        /// </summary>
        [Test]
        public void TestVerifyNamesAnAbsentArgument()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);

            byte[] message = new byte[]{ 1, 2, 3 };

            signer.BlockUpdate(message, 0, message.Length);

            byte[] signature = signer.GenerateSignature();
            XmssSigner verifier = new XmssSigner();

            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(message, 0, message.Length);

            Assert.IsTrue(verifier.VerifySignature(signature));
            CheckAbsentSignature(verifier, message);

            // a signature that is present but will not decode is still an answer, not an error
            verifier.BlockUpdate(message, 0, message.Length);
            Assert.IsFalse(verifier.VerifySignature(new byte[0]));

            // straight at the engine, which is where the check lives
            CheckAbsentSignature((XmssPublicKeyParameters)kp.Public, message);

            Assert.IsFalse(XmssEngine.VerifySignature((XmssPublicKeyParameters)kp.Public, message, new byte[0]));
        }

        private static void CheckAbsentSignature(XmssPublicKeyParameters publicKey, byte[] message)
        {
            ArgumentNullException e = Assert.Throws<ArgumentNullException>(
                () => XmssEngine.VerifySignature(publicKey, message, null), "absent signature accepted");
            Assert.AreEqual("signature", e.ParamName);
            StringAssert.StartsWith("signature == null", e.Message);
        }

        private static void CheckAbsentSignature(XmssSigner verifier, byte[] message)
        {
            verifier.BlockUpdate(message, 0, message.Length);

            ArgumentNullException e = Assert.Throws<ArgumentNullException>(() => verifier.VerifySignature(null),
                "absent signature accepted");
            Assert.AreEqual("signature", e.ParamName);
            StringAssert.StartsWith("signature == null", e.Message);
        }

        /// <summary>
        /// <see cref="XmssSigner.GetUsagesRemaining"/> answers for the key the signer is holding, so the three states
        /// that leave it holding none - never initialised, initialised for verification, and key already collected -
        /// all report zero signatures left rather than raising on the absent key.
        /// </summary>
        [Test]
        public void TestUsagesRemainingReportedAsZeroWhenNoKeyHeld()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();

            Assert.AreEqual(0, new XmssSigner().GetUsagesRemaining());

            XmssSigner verifier = new XmssSigner();

            verifier.Init(false, kp.Public);
            Assert.AreEqual(0, verifier.GetUsagesRemaining());

            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);

            // the positive control: while the signer holds the key it reports the key's own count, which for a
            // freshly generated key is one signature per leaf of the tree
            Assert.AreEqual(1 << Height, signer.GetUsagesRemaining());

            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);
            signer.GenerateSignature();
            signer.GetUpdatedPrivateKey();

            Assert.AreEqual(0, signer.GetUsagesRemaining());
        }

        /// <summary>
        /// Review focus: a private key encoded after N signatures and decoded again signs at index N, never at an
        /// earlier one.
        /// </summary>
        [Test]
        public void RoundTripAfterSigning_ContinuesAtNextIndex()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            AsymmetricCipherKeyPair kp = XmssKeyPair(parameters);
            byte[] message = new byte[]{ 1, 2, 3 };

            XmssSigner signer = new XmssSigner();
            signer.Init(true, kp.Private);
            for (int i = 0; i != 3; i++)
            {
                Assert.AreEqual(i, XmssHarnessTests.IndexOf(XmssHarnessTests.Sign(signer, message)));
            }

            byte[] stored = ((XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey()).GetEncoded();
            Assert.AreEqual(3, XmssHarnessTests.IndexOf(stored));

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(stored).Build();
            Assert.AreEqual(3, restored.Index);

            XmssSigner next = new XmssSigner();
            next.Init(true, restored);
            byte[] signature = XmssHarnessTests.Sign(next, message);
            Assert.AreEqual(3, XmssHarnessTests.IndexOf(signature));

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, message, signature));

            // and what is collected for storing next is the position after the one just spent
            Assert.AreEqual(4, ((XmssPrivateKeyParameters)next.GetUpdatedPrivateKey()).Index);
        }

        /// <summary>
        /// Reset(), re-initialising on the same key, and a collection between signatures never hand the same index
        /// out twice.
        /// </summary>
        [Test]
        public void ResetAndReInitNeverReuseAnIndex()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            byte[] message = new byte[]{ 1, 2, 3 };

            XmssSigner signer = new XmssSigner();
            signer.Init(true, privKey);
            int first = XmssHarnessTests.IndexOf(XmssHarnessTests.Sign(signer, message));

            signer.Reset();
            int second = XmssHarnessTests.IndexOf(XmssHarnessTests.Sign(signer, message));

            signer.Init(true, privKey);
            int third = XmssHarnessTests.IndexOf(XmssHarnessTests.Sign(signer, message));

            Assert.AreSame(privKey, signer.GetUpdatedPrivateKey());
            signer.Init(true, privKey);
            int fourth = XmssHarnessTests.IndexOf(XmssHarnessTests.Sign(signer, message));

            CollectionAssert.AreEqual(new int[]{ 0, 1, 2, 3 }, new int[]{ first, second, third, fourth });
            Assert.AreEqual(4, privKey.Index);
        }
    }
}
