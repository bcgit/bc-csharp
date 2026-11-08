using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Test cases for XmssReducedSignature class.
    /// </summary>
    /// <remarks>
    /// The two Java parsing tests take their reduced signature out of an XMSS^MT signature. The methods after
    /// <see cref="TestConstructor"/> check the same encoding on reduced signatures assembled from their parts.
    /// </remarks>
    [TestFixture]
    public class XmssReducedSignatureTests
    {
        [Test]
        public void TestSignatureParsingSha256()
        {
            CheckSignatureParsing(new XmssMTParameters(8, 2, new Sha256Digest()),
                new XmssParameters(4, new Sha256Digest()));
        }

        [Test]
        public void TestSignatureParsingSha512()
        {
            CheckSignatureParsing(new XmssMTParameters(4, 2, new Sha512Digest()),
                new XmssParameters(2, new Sha512Digest()));
        }

        private static void CheckSignatureParsing(XmssMTParameters parameters, XmssParameters layerParameters)
        {
            XmssHarnessTests.XmssMT mt = new XmssHarnessTests.XmssMT(parameters, new XmssHarnessTests.NullPrng());
            mt.GenerateKeys();
            byte[] message = new byte[1024];
            byte[] sig1 = mt.Sign(message);
            XmssMTSignature sig2 = new XmssMTSignature.Builder(parameters).WithSignature(sig1).Build();

            XmssReducedSignature reducedSignature1 = sig2.ReducedSignatures[0];
            byte[] reducedSignatureBinary = reducedSignature1.ToByteArray();
            XmssReducedSignature reducedSignature2 = new XmssReducedSignature.Builder(layerParameters)
                .WithReducedSignature(reducedSignatureBinary, 0).Build();

            Assert.IsTrue(Arrays.AreEqual(reducedSignatureBinary, reducedSignature2.ToByteArray()));
        }

        [Test]
        public void TestConstructor()
        {
            XmssReducedSignature sig = new XmssReducedSignature.Builder(new XmssParameters(4, new Sha512Digest()))
                .Build();

            byte[] sigByte = sig.ToByteArray();
            /* check everything is 0 */
            for (int i = 0; i < sigByte.Length; i++)
            {
                Assert.AreEqual(0x00, sigByte[i]);
            }
        }

        /// <summary>
        /// A reduced signature read out of the middle of a larger encoding, as XMSS and XMSS^MT signatures hold
        /// them, writes back the bytes it was read from.
        /// </summary>
        [Test]
        public void ReducedSignatureParsingAtAnOffset()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] reduced = Assembled(p).ToByteArray();

            Assert.AreEqual(XmssReducedSignature.SizeOf(p), reduced.Length);
            Assert.AreEqual((67 + 4) * 32, reduced.Length);

            byte[] framed = Arrays.ConcatenateAll(new byte[7], reduced, new byte[5]);
            XmssReducedSignature parsed = new XmssReducedSignature.Builder(p).WithReducedSignature(framed, 7)
                .Build();

            Assert.IsTrue(Arrays.AreEqual(reduced, parsed.ToByteArray()));
            Assert.AreEqual(p.Height, parsed.AuthPath.Count);
            for (int i = 0; i < p.Height; i++)
            {
                Assert.AreEqual(i, parsed.AuthPath[i].Height);
            }

            byte[] output = new byte[framed.Length];
            parsed.EncodeTo(output, 7);
            Assert.IsTrue(Arrays.AreEqual(Arrays.CopyOfRange(framed, 7, 7 + reduced.Length),
                Arrays.CopyOfRange(output, 7, 7 + reduced.Length)));
        }

        [Test]
        public void ReducedSignatureWrongSizeRejected()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] reduced = Assembled(p).ToByteArray();

            int[][] cases = new int[][]
            {
                new int[]{ reduced.Length - 1, 0 },
                new int[]{ reduced.Length, 1 },
                new int[]{ reduced.Length, -1 },
                new int[]{ 0, 0 },
            };

            foreach (int[] c in cases)
            {
                byte[] encoding = Arrays.CopyOf(reduced, c[0]);
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssReducedSignature.Builder(p).WithReducedSignature(encoding, c[1]).Build());
                Assert.AreEqual("signature has wrong size", e.Message);
            }

            List<XmssNode> shortPath = new List<XmssNode>(Assembled(p).AuthPath);
            shortPath.RemoveAt(shortPath.Count - 1);
            Assert.Throws<ArgumentException>(
                () => new XmssReducedSignature.Builder(p).WithAuthPath(shortPath).Build());
        }

        private static XmssReducedSignature Assembled(XmssParameters p)
        {
            byte[][] wotsPlusSignature = new byte[p.Len][];
            for (int i = 0; i < p.Len; i++)
            {
                wotsPlusSignature[i] = BdsStateSerializationTests.Seed(p, i);
            }
            List<XmssNode> authPath = new List<XmssNode>();
            for (int i = 0; i < p.Height; i++)
            {
                authPath.Add(new XmssNode(i, BdsStateSerializationTests.Seed(p, 0xa0 + i)));
            }
            return new XmssReducedSignature.Builder(p)
                .WithWotsPlusSignature(wotsPlusSignature)
                .WithAuthPath(authPath)
                .Build();
        }
    }
}
