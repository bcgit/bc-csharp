using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A stateful private key records where it has got to, and what tree it belongs to, in more than one place, and
    /// the records are compared where a key is built.
    /// </summary>
    /// <remarks>
    /// The XMSS key records its root twice - its own root field, and the root node inside the BDS traversal state -
    /// and an XMSS^MT key does the same with the root of its top layer's state. An XMSS^MT key also records its
    /// position twice - its index, and its per-layer traversal states - and the index cross-checks refuse a key whose
    /// two records disagree where it is encoded, rolled or signed with.
    /// </remarks>
    [TestFixture]
    public class PositionRecordCrossCheckTests
    {
        private const int Height = 6;
        private const int Layers = 3;

        /// <summary>
        /// A root that disagrees is a key built around a traversal state describing a different tree. Signatures
        /// made from it carry authentication paths to that other root, so they do not verify under the public key
        /// the caller believes it holds (bc-java github #2414).
        /// </summary>
        [Test]
        public void TestARootThatDisagreesWithTheStateIsRefused()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            // through the builder, where a restored state meets a root supplied beside it
            byte[] wrongRoot = Arrays.Clone(privKey.GetRoot());

            wrongRoot[0] ^= 0x01;

            ArgumentException e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(
                parameters).WithSecretKeySeed(privKey.GetSecretKeySeed()).WithSecretKeyPrf(privKey.GetSecretKeyPrf())
                .WithPublicSeed(privKey.GetPublicSeed()).WithRoot(wrongRoot)
                .WithBdsState(privKey.GetBdsState()).Build(),
                "a key whose root disagrees with its traversal state was built");
            Assert.AreEqual("BDS state root does not match the private key root", e.Message);

            // and through the encoded-key path, where the two arrive in one byte string: every byte of the root
            // field, so the comparison cannot be of a prefix
            byte[] encoded = privKey.GetEncoded();
            int n = parameters.TreeDigestSize;
            int rootOffset = 4 + 3 * n;

            for (int b = 0; b != n; b++)
            {
                byte[] corrupt = Arrays.Clone(encoded);

                corrupt[rootOffset + b] ^= 0x01;

                e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "corrupt root byte " + b + " accepted");
                Assert.AreEqual("BDS state root does not match the private key root", e.Message, "byte " + b);
            }

            // the harness: the encoding these were made from is accepted and carries the same root
            XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(encoded).Build();

            Assert.IsTrue(Arrays.AreEqual(privKey.GetRoot(), decoded.GetRoot()));
        }

        /// <summary>
        /// A state carries no root until it has one, so the root comparison is made only when both sides have a
        /// value; a version that refused the absent case would refuse the placeholder state of a spent key. A key
        /// built from its seeds without a root is refused by the builder instead, before any comparison.
        /// </summary>
        [Test]
        public void TestAnAbsentRootOnEitherSideIsNotAMismatch()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            Bds state = privKey.GetBdsState();

            // a state with a real root, asked about a key that declares none
            state.ValidateRoot(null);

            // the key that declares none: the builder refuses it, since the root keys H_msg
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() =>
                new XmssPrivateKeyParameters.Builder(parameters)
                    .WithSecretKeySeed(privKey.GetSecretKeySeed()).WithSecretKeyPrf(privKey.GetSecretKeyPrf())
                    .WithPublicSeed(privKey.GetPublicSeed())
                    .WithBdsState(state).Build());
            Assert.AreEqual("root is null", e.Message);

            // the other side absent: an XMSS^MT layer is built lazily, so a map whose top layer is not there yet has
            // nothing to compare and must not be refused for it
            XmssMTParameters mtParams = new XmssMTParameters(Height, Layers, new Sha256Digest());

            new BdsStateMap(1L << Height).ValidateRoot(mtParams, privKey.GetRoot());
        }

        /// <summary>
        /// The XMSS^MT counterpart of <see cref="TestARootThatDisagreesWithTheStateIsRefused"/>: the top tree's root
        /// is the public root, so the top layer's state carries a second copy of the key's root, and a stored key
        /// whose two copies disagree is refused.
        /// </summary>
        [Test]
        public void TestATopLayerRootThatDisagreesIsRefused()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            Assert.IsNotNull(privKey.GetBdsState().Get(Layers - 1), "no top layer state to compare against");

            byte[] encoded = privKey.GetEncoded();
            int n = parameters.TreeDigestSize;
            int rootOffset = (parameters.Height + 7) / 8 + 3 * n;

            for (int b = 0; b != n; b++)
            {
                byte[] corrupt = Arrays.Clone(encoded);

                corrupt[rootOffset + b] ^= 0x01;

                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "corrupt root byte " + b + " accepted");
                Assert.AreEqual("BDS state root does not match the private key root", e.Message, "byte " + b);
            }

            XmssMTPrivateKeyParameters decoded =
                new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoded).Build();

            Assert.IsTrue(Arrays.AreEqual(privKey.GetRoot(), decoded.GetRoot()));
        }

        /// <summary>
        /// The compatibility half. Walk a key across every index it has, encoding at each one, and confirm the
        /// encoding still decodes to a key that signs verifiably. A cross-check that is too strict rejects legitimate
        /// keys - the boundary at a leaf index of 0, where a layer legitimately still shows the previous subtree's
        /// last leaf, is the case that makes that a real risk here.
        /// </summary>
        [Test]
        [Explicit] // slow: ~13s
        public void TestEveryIndexOfAKeyStillEncodesAndSigns()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pubKey = (XmssMTPublicKeyParameters)kp.Public;

            long maxIndex = privKey.GetBdsState().MaxIndex;

            for (long index = 0; index <= maxIndex; index++)
            {
                Assert.AreEqual(index, privKey.Index, "key is not where the walk expects it");

                byte[] encoded = privKey.GetEncoded();
                XmssMTPrivateKeyParameters decoded = new XmssMTPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(encoded).Build();

                Assert.AreEqual(index, decoded.Index, "decoded key sits at a different index");

                byte[] message = new byte[]{ (byte)index, (byte)(index >> 8) };

                XmssMTSigner signer = new XmssMTSigner();
                signer.Init(true, decoded);
                signer.BlockUpdate(message, 0, message.Length);
                byte[] signature = signer.GenerateSignature();

                XmssMTSigner verifier = new XmssMTSigner();
                verifier.Init(false, pubKey);
                verifier.BlockUpdate(message, 0, message.Length);
                Assert.IsTrue(verifier.VerifySignature(signature), "signature at index " + index + " does not verify");

                privKey.RollKey();
            }

            // and the exhausted key past the end, whose state map is empty and so has no layer to disagree with
            // anything
            Assert.AreEqual(maxIndex + 1, privKey.Index);
            Assert.AreEqual(0, privKey.GetUsagesRemaining());
        }

        /// <summary>
        /// A layer zero state left behind where the index has moved on - what a partial write or a storage layer that
        /// restored half a key produces - must not be written out as a key, because decoding it back is refused and
        /// because the position it describes is one the key has already signed at.
        /// </summary>
        [Test]
        public void TestEncodingRefusesAStateThatLagsTheIndex()
        {
            XmssMTPrivateKeyParameters privKey = Desynchronised();

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => privKey.GetEncoded(),
                "a key whose two records of its position disagree was encoded");
            StringAssert.StartsWith("BDS state has wrong index for layer 0", e.Message);
        }

        /// <summary>
        /// The same pair, refused where it next moves rather than where it is written: a roll carries a lagging state
        /// forward rather than repairing it, so the key would go on signing at positions its state says it has
        /// already been to.
        /// </summary>
        [Test]
        public void TestRollRefusesAStateThatLagsTheIndex()
        {
            XmssMTPrivateKeyParameters privKey = Desynchronised();

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => privKey.RollKey(),
                "a key whose two records of its position disagree was rolled");
            StringAssert.StartsWith("BDS state has wrong index for layer 0", e.Message);
        }

        /// <summary>
        /// The same pair again, refused where it would be spent. The roll runs from the finally the signature is built
        /// inside, so leaving the refusal to it would spend the one-time key and advance the key before the exception
        /// is raised; the assertion on the index is the one that matters.
        /// </summary>
        [Test]
        public void TestSigningRefusesAStateThatLagsTheIndex()
        {
            XmssMTPrivateKeyParameters privKey = Desynchronised();

            long index = privKey.Index;

            XmssMTSigner signer = new XmssMTSigner();

            signer.Init(true, privKey);
            signer.BlockUpdate(new byte[]{ 0x01 }, 0, 1);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => signer.GenerateSignature(),
                "a key whose two records of its position disagree signed");
            StringAssert.StartsWith("BDS state has wrong index for layer 0", e.Message);

            Assert.AreEqual(index, privKey.Index, "a refused signature must not move the key");
        }

        /// <summary>
        /// A key sitting at an index its own layer zero state does not agree with, built the way the failure actually
        /// arises: the state map the key holds is the live one, so a layer zero state kept from before a roll can be
        /// put back into it afterwards, which is what a half-restored key looks like from the inside.
        /// </summary>
        private static XmssMTPrivateKeyParameters Desynchronised()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            // sign twice so layer zero exists and is off the subtree boundary the cross-check allows
            XmssMTSigner signer = new XmssMTSigner();
            signer.Init(true, privKey);
            for (int i = 0; i != 2; i++)
            {
                signer.BlockUpdate(new byte[]{ (byte)i }, 0, 1);
                signer.GenerateSignature();
            }

            Bds stale = privKey.GetBdsState().Get(0);
            Assert.IsNotNull(stale, "no layer zero state to keep");

            privKey.RollKey();
            Assert.AreNotEqual(XmssUtilities.GetLeafIndex(privKey.Index, Height / Layers), stale.Index,
                "layer zero already agrees with the index after the roll");

            privKey.GetBdsState().Put(0, stale);

            return privKey;
        }
    }
}
