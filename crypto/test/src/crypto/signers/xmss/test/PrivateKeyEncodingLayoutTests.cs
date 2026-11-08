using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Where each field of a stored private key sits, and which bytes its trailing checksum covers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A round trip cannot see any of this: encode and decode are the same implementation read in two directions, so
    /// a change that moves a field, or that alters what the checksum is taken over, moves both halves together and
    /// the key still comes back. What is asserted here is the part an agreeing pair of directions cannot establish:
    /// the offsets, taken from this file rather than from the codec's own constants, and the checksum recomputed here.
    /// </para>
    /// <para>
    /// testXmssMtKeyEncodingLayout arrives with the XMSS^MT signer. <see cref="XmssKeyEncodingLayout_Rolled"/> checks
    /// the same layout on a key moved on by RollKey(), from index 0.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class PrivateKeyEncodingLayoutTests
    {
        private const int BdsStateMagic = 0x42445300;
        private const int StateVersion = 1;
        private const int ChecksumSize = 32;

        /// <summary>index(4) || secretKeySeed(n) || secretKeyPRF(n) || publicSeed(n) || root(n) || BDS state.</summary>
        [Test]
        public void TestXmssKeyEncodingLayout()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);

            // three indices: the state stored at index 1 holds far fewer nodes than one further in
            for (int index = 0; index != 3; index++)
            {
                signer.Update((byte)index);
                signer.GenerateSignature();

                // the key to store, which is the one after the index just spent
                XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();
                int n = parameters.TreeDigestSize;
                byte[] encoding = privKey.GetEncoded();

                Assert.AreEqual(index + 1, (int)Pack.BE_To_UInt32(encoding, 0));
                CheckFields(encoding, 4, n, privKey.GetSecretKeySeed(), privKey.GetSecretKeyPrf(),
                    privKey.GetPublicSeed(), privKey.GetRoot());
                CheckState(encoding, 4 + 4 * n, BdsStateMagic, privKey.GetPublicSeed());

                // the asserted bytes are also what the key they decode to encodes back to, so this is the layout of a
                // stored key however it was arrived at, not only of a freshly rolled one
                XmssPrivateKeyParameters rebuilt = new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(encoding).Build();

                Assert.IsTrue(Arrays.AreEqual(encoding, rebuilt.GetEncoded()), "re-encoded");

                // GetUpdatedPrivateKey() took the key with it, so the signer needs it back to go on
                signer.Init(true, privKey);
            }
        }

        /// <summary>As <see cref="TestXmssKeyEncodingLayout"/>, on a key moved on by RollKey().</summary>
        [Test]
        public void XmssKeyEncodingLayout_Rolled()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            int n = parameters.TreeDigestSize;

            for (int index = 0; index != 4; index++)
            {
                byte[] encoding = privKey.GetEncoded();

                Assert.AreEqual(index, (int)Pack.BE_To_UInt32(encoding, 0));
                CheckFields(encoding, 4, n, privKey.GetSecretKeySeed(), privKey.GetSecretKeyPrf(),
                    privKey.GetPublicSeed(), privKey.GetRoot());
                CheckState(encoding, 4 + 4 * n, BdsStateMagic, privKey.GetPublicSeed());

                XmssPrivateKeyParameters rebuilt = new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(encoding).Build();

                Assert.IsTrue(Arrays.AreEqual(encoding, rebuilt.GetEncoded()), "re-encoded");

                privKey.RollKey();
            }
        }

        private static void CheckFields(byte[] encoding, int offset, int n, byte[] secretKeySeed, byte[] secretKeyPrf,
            byte[] publicSeed, byte[] root)
        {
            Assert.IsTrue(Arrays.AreEqual(secretKeySeed, Arrays.CopyOfRange(encoding, offset, offset + n)),
                "secretKeySeed");
            Assert.IsTrue(Arrays.AreEqual(secretKeyPrf, Arrays.CopyOfRange(encoding, offset + n, offset + 2 * n)),
                "secretKeyPRF");
            Assert.IsTrue(Arrays.AreEqual(publicSeed, Arrays.CopyOfRange(encoding, offset + 2 * n, offset + 3 * n)),
                "publicSeed");
            Assert.IsTrue(Arrays.AreEqual(root, Arrays.CopyOfRange(encoding, offset + 3 * n, offset + 4 * n)),
                "root");
        }

        /// <summary>
        /// The state's header where the fixed fields end, and the checksum over everything from there to the last
        /// 32 bytes - SHA-256 whatever the tree digest is, with the key's public seed in front.
        /// </summary>
        private static void CheckState(byte[] encoding, int stateOffset, int magic, byte[] publicSeed)
        {
            int bodyLength = encoding.Length - ChecksumSize - stateOffset;

            Assert.IsTrue(bodyLength > 8, "state too short");
            Assert.AreEqual(magic, (int)Pack.BE_To_UInt32(encoding, stateOffset), "state magic");
            Assert.AreEqual(StateVersion, (int)Pack.BE_To_UInt32(encoding, stateOffset + 4), "state version");

            IDigest digest = new Sha256Digest();

            digest.BlockUpdate(publicSeed, 0, publicSeed.Length);
            digest.BlockUpdate(encoding, stateOffset, bodyLength);

            byte[] expected = new byte[digest.GetDigestSize()];

            digest.DoFinal(expected, 0);

            Assert.IsTrue(Arrays.AreEqual(expected,
                Arrays.CopyOfRange(encoding, encoding.Length - ChecksumSize, encoding.Length)), "state checksum");
        }
    }
}
