using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// <see cref="BdsStateMap.Validate(XmssMTParameters, long, byte[], byte[])"/> ties each layer's BDS traversal
    /// state to the enclosing key's global index, and admits one specific carry-over at a leaf index of 0: a layer's
    /// state may still show the final leaf of the subtree before, because UpdateState() does not advance a layer's
    /// state on the last leaf of its subtree - the state is rebuilt from scratch the next time that layer signs.
    /// Walking every index of the five parameter sets the method cites is what shows no other divergence.
    /// </summary>
    [TestFixture]
    public class BdsStateMapIndexEnumerationTests
    {
        /// <summary>
        /// Every index a key of each cited parameter set can reach - 0 up to and including the one-past-the-end
        /// exhausted index - is checked directly against the state map's validation. A boundary case the claim
        /// missed would surface as an unexpected <see cref="InvalidOperationException"/> partway through.
        /// </summary>
        [Test]
        [Explicit] // slow: ~45s
        public void TestEveryIndexOfCitedParameterSetsValidates()
        {
            WalkEveryIndex(4, 2);
            WalkEveryIndex(6, 2);
            WalkEveryIndex(6, 3);
            WalkEveryIndex(9, 3);
            WalkEveryIndex(8, 4);
        }

        /// <summary>
        /// Two of the cited parameter sets, walked as <see cref="TestEveryIndexOfCitedParameterSetsValidates"/> walks
        /// all five, so the default run keeps the subtree boundary allowance covered at one and at two layers above
        /// the bottom.
        /// </summary>
        [Test]
        public void EveryIndexOfTheSmallestCitedParameterSetsValidates()
        {
            WalkEveryIndex(4, 2);
            WalkEveryIndex(6, 3);
        }

        private static void WalkEveryIndex(int height, int layers)
        {
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;
            long maxIndex = privKey.GetBdsState().MaxIndex;
            string label = "h=" + height + "/d=" + layers;

            for (long expectedIndex = 0; expectedIndex <= maxIndex + 1; expectedIndex++)
            {
                Assert.AreEqual(expectedIndex, privKey.Index, label);

                privKey.GetBdsState().Validate(parameters, privKey.Index, privKey.GetPublicSeed(),
                    privKey.GetSecretKeySeed());

                if (expectedIndex < maxIndex + 1)
                {
                    privKey.RollKey();
                }
            }
        }

        /// <summary>
        /// The check has teeth: a global index rolled back against traversal state that stayed advanced is exactly
        /// the divergence RFC 8391 sec. 1.1 requires be refused, since signing again there would reuse a one-time
        /// key and the signature would still verify.
        /// </summary>
        [Test]
        public void TestRolledBackIndexStillRejected()
        {
            XmssMTParameters parameters = new XmssMTParameters(6, 3, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kpg.GenerateKeyPair().Private;

            for (int i = 0; i != 5; i++)
            {
                privKey.RollKey();
            }

            byte[] encoded = privKey.GetEncoded();
            int indexSize = (parameters.Height + 7) / 8;

            // roll the declared index back to 0 while leaving the traversal state - which has genuinely advanced to
            // index 5 - untouched
            for (int i = 0; i < indexSize; i++)
            {
                encoded[i] = 0;
            }

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoded).Build());
            StringAssert.StartsWith("BDS state has wrong index for layer", e.Message);
        }

        /// <summary>
        /// The carry-over is the one place a leaf index cannot tell two positions apart: a layer state on the last
        /// leaf of a subtree is legitimate where the index names leaf 0 of the next subtree, and is what a key whose
        /// index has been moved back to leaf 0 of the same subtree, or of the first, also shows. Both rollbacks would
        /// sign again at indices already used, with signatures that verify; both are refused when the key is read.
        /// </summary>
        [Test]
        public void TestIndexMovedBackOntoACarryOverPositionRejected()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kp.Private;
            byte[] message = new byte[]{ 1, 2, 3 };

            // to index 3, the last leaf of the first layer zero subtree: the review's case, index 3 written as 0
            for (int i = 0; i != 3; i++)
            {
                XmssEngine.GenerateMTSignature(privKey, message);
            }
            CheckRefusedAt(parameters, privKey.GetEncoded(), 0);

            // and to index 7, the last leaf of the second, written as 4, leaf 0 of that same subtree: the layer above
            // is on the same leaf at 4 as at 7, so only the subtree tells the two apart
            for (int i = 0; i != 4; i++)
            {
                XmssEngine.GenerateMTSignature(privKey, message);
            }
            CheckRefusedAt(parameters, privKey.GetEncoded(), 4);

            // the honest encoding still reads back, and signs on from where it is
            XmssMTPrivateKeyParameters decoded = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privKey.GetEncoded()).Build();
            byte[] signature = XmssEngine.GenerateMTSignature(decoded, message);
            Assert.AreEqual(7L, SignatureIndex(signature, parameters));
            Assert.IsTrue(XmssEngine.VerifyMTSignature((XmssMTPublicKeyParameters)kp.Public, message, signature));
        }

        /// <summary>The index an XMSS^MT signature opens with, in ceil(h / 8) bytes (RFC 8391 sec. 4.2.5).</summary>
        private static long SignatureIndex(byte[] signature, XmssMTParameters parameters)
        {
            long index = 0;
            for (int i = 0; i != (parameters.Height + 7) / 8; i++)
            {
                index = (index << 8) | signature[i];
            }
            return index;
        }

        private static void CheckRefusedAt(XmssMTParameters parameters, byte[] encoded, int index)
        {
            // a one-byte index field at a total height of 4
            Assert.AreEqual(1, (parameters.Height + 7) / 8);
            encoded[0] = (byte)index;

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(encoded).Build(),
                "index moved back to " + index);
            Assert.AreEqual("BDS state has wrong index for layer 0: expected 0 but state is at 3", e.Message);
        }

        /// <summary>
        /// The other side of <see cref="TestIndexMovedBackOntoACarryOverPositionRejected"/>: at every index of a
        /// hypertree, across every subtree boundary on one layer and on two, a key written out and read back is
        /// accepted, and its signature on the first leaf of each subtree verifies.
        /// </summary>
        [Test]
        public void TestEveryRolloverReadsBackAndSigns()
        {
            CheckEveryRolloverReadsBackAndSigns(4, 2);
            CheckEveryRolloverReadsBackAndSigns(6, 3);
        }

        private static void CheckEveryRolloverReadsBackAndSigns(int height, int layers)
        {
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPublicKeyParameters pubKey = (XmssMTPublicKeyParameters)kp.Public;
            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kp.Private;
            byte[] message = new byte[]{ 1, 2, 3 };
            string label = "h=" + height + "/d=" + layers;

            int subtreeLeaves = 1 << (height / layers);
            for (long index = 0; index != 1L << height; index++)
            {
                privKey = new XmssMTPrivateKeyParameters.Builder(parameters).WithPrivateKey(privKey.GetEncoded())
                    .Build();

                // a signature on the first leaf of each layer zero subtree, where some layer is on its carry-over
                // position; the key is rolled over the rest, which is read back just the same
                if (index % subtreeLeaves != 0)
                {
                    privKey.RollKey();
                    continue;
                }

                byte[] signature = XmssEngine.GenerateMTSignature(privKey, message);
                Assert.AreEqual(index, SignatureIndex(signature, parameters), label);
                Assert.IsTrue(XmssEngine.VerifyMTSignature(pubKey, message, signature), label + " index " + index);
            }
        }
    }
}
