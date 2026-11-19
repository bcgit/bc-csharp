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
    /// and these are the XMSS methods, and the XMSS half of <see cref="TestAnAbsentRootOnEitherSideIsNotAMismatch"/>.
    /// The index cross-checks are XMSS^MT ones and arrive with the XMSS^MT keys and signer.
    /// </remarks>
    [TestFixture]
    public class PositionRecordCrossCheckTests
    {
        private const int Height = 6;

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
        /// <remarks>XMSS half: the lazily built XMSS^MT layer arrives with the XMSS^MT state map.</remarks>
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
        }
    }
}
