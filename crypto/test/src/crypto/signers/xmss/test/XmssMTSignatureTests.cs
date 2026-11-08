using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>Test cases for the XMSS^MT signature class.</summary>
    /// <remarks>
    /// The methods after <see cref="TestConstructor"/> cover the decode refusals the XMSS signature fixture covers
    /// for its own encoding.
    /// </remarks>
    [TestFixture]
    public class XmssMTSignatureTests
    {
        [Test]
        public void TestSignatureParsingSha256()
        {
            int totalHeight = 6;
            int layers = 3;
            byte[] message = new byte[1024];
            XmssMTParameters parameters = new XmssMTParameters(totalHeight, layers, new Sha256Digest());
            XmssHarnessTests.XmssMT xmssMT = new XmssHarnessTests.XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] signature1 = xmssMT.Sign(message);
            XmssMTSignature mtSignature = new XmssMTSignature.Builder(parameters).WithSignature(signature1).Build();
            byte[] signature2 = mtSignature.ToByteArray();
            Assert.IsTrue(Arrays.AreEqual(signature1, signature2));
        }

        [Test]
        public void TestConstructor()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMTSignature sig = new XmssMTSignature.Builder(parameters).Build();

            byte[] sigByte = sig.ToByteArray();
            /* check everything is 0 */
            for (int i = 0; i < sigByte.Length; i++)
            {
                Assert.AreEqual(0x00, sigByte[i]);
            }
        }

        /// <summary>
        /// The index field is the fewest whole bytes that hold a leaf index of the hypertree, and the encoding is
        /// that, the randomizer and one reduced signature per layer.
        /// </summary>
        [Test]
        public void EncodedSizes()
        {
            int[][] cases = new int[][]{ new int[]{ 4, 2, 1 }, new int[]{ 8, 2, 1 }, new int[]{ 9, 3, 2 },
                new int[]{ 20, 2, 3 }, new int[]{ 40, 4, 5 }, new int[]{ 60, 12, 8 } };

            foreach (int[] c in cases)
            {
                XmssMTParameters parameters = new XmssMTParameters(c[0], c[1], NistObjectIdentifiers.IdSha256);

                Assert.AreEqual(c[2], XmssMTSignature.IndexSizeOf(parameters), "h=" + c[0]);
                Assert.AreEqual(c[2] + 32 + c[1] * (67 + c[0] / c[1]) * 32, XmssMTSignature.EncodedSizeOf(parameters),
                    "h=" + c[0]);
            }
        }

        /// <summary>
        /// A fixed-size encoding: anything longer or shorter, a valid signature with trailing data included, is not
        /// a signature for these parameters, and an absent one is the caller's mistake.
        /// </summary>
        [Test]
        public void SignatureWrongSizeRejected()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            int size = XmssMTSignature.EncodedSizeOf(parameters);

            foreach (int length in new int[]{ 0, 1, size - 1, size + 1 })
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTSignature.Builder(parameters).WithSignature(new byte[length]).Build(),
                    "length " + length);
                Assert.AreEqual("signature has wrong size", e.Message);
            }

            Assert.Throws<ArgumentNullException>(() => new XmssMTSignature.Builder(parameters).WithSignature(null));

            Assert.AreEqual(0, new XmssMTSignature.Builder(parameters).WithSignature(new byte[size]).Build().Index);
        }

        /// <summary>
        /// The index field is wider than the hypertree's index at most heights, so an encoding can name a leaf the
        /// key does not have; at a total height that needs all eight bytes it can name a negative one.
        /// </summary>
        [Test]
        public void SignatureIndexOutOfTreeRejected()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            int size = XmssMTSignature.EncodedSizeOf(parameters);

            for (int index = 0; index != 256; index++)
            {
                byte[] encoded = new byte[size];
                encoded[0] = (byte)index;

                if (index < 16)
                {
                    Assert.AreEqual(index, new XmssMTSignature.Builder(parameters).WithSignature(encoded).Build()
                        .Index);
                }
                else
                {
                    ArgumentException e = Assert.Throws<ArgumentException>(
                        () => new XmssMTSignature.Builder(parameters).WithSignature(encoded).Build(),
                        "index " + index);
                    Assert.AreEqual("index out of bounds", e.Message);
                }
            }

            XmssMTParameters tall = new XmssMTParameters(60, 30, NistObjectIdentifiers.IdSha256);
            byte[] negative = new byte[XmssMTSignature.EncodedSizeOf(tall)];
            negative[0] = 0x80;
            InvalidOperationException ie = Assert.Throws<InvalidOperationException>(
                () => new XmssMTSignature.Builder(tall).WithSignature(negative).Build());
            Assert.AreEqual("index must not be negative", ie.Message);
        }

        /// <summary>
        /// A signature that will not decode is a failed verification rather than an exception; an absent one is
        /// raised.
        /// </summary>
        [Test]
        public void VerifyRejectsMalformedSignatures()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new XmssHarnessTests.NullPrng(), parameters));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPublicKeyParameters pub = (XmssMTPublicKeyParameters)kp.Public;
            byte[] message = new byte[]{ 1, 2, 3 };

            byte[] sig = XmssEngine.GenerateMTSignature((XmssMTPrivateKeyParameters)kp.Private, message);
            Assert.IsTrue(XmssEngine.VerifyMTSignature(pub, message, sig));
            Assert.IsFalse(XmssEngine.VerifyMTSignature(pub, new byte[]{ 1, 2, 4 }, sig));

            byte[] badIndex = Arrays.Clone(sig);
            badIndex[0] = 16;
            Assert.IsFalse(XmssEngine.VerifyMTSignature(pub, message, badIndex));

            badIndex[0] = 1;
            Assert.IsFalse(XmssEngine.VerifyMTSignature(pub, message, badIndex));

            Assert.IsFalse(XmssEngine.VerifyMTSignature(pub, message, Arrays.CopyOf(sig, sig.Length - 1)));
            Assert.IsFalse(XmssEngine.VerifyMTSignature(pub, message, Arrays.Append(sig, 0)));

            ArgumentNullException e = Assert.Throws<ArgumentNullException>(
                () => XmssEngine.VerifyMTSignature(pub, message, null));
            Assert.AreEqual("signature", e.ParamName);
        }
    }
}
