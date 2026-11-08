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
    /// Test cases for XmssSignature class.
    /// </summary>
    /// <remarks>
    /// The Java methods that take their signature from a generated key - the two parsing tests,
    /// testSignatureWrongSizeRejected and testVerifyRejectsWrongSize - arrive with the signer and its test harness.
    /// The methods after <see cref="TestConstructor"/> check the same encoding on signatures assembled from their
    /// parts, and the verifier's root computation on an authentication path the BDS state hands out.
    /// </remarks>
    [TestFixture]
    public class XmssSignatureTests
    {
        [Test]
        public void TestConstructor()
        {
            XmssParameters p = new XmssParameters(10, new Sha256Digest());
            XmssSignature sig = new XmssSignature.Builder(p).Build();

            byte[] sigByte = sig.ToByteArray();
            /* check everything is 0 */
            for (int i = 0; i < sigByte.Length; i++)
            {
                Assert.AreEqual(0x00, sigByte[i]);
            }
        }

        [Test]
        public void SignatureParsingRoundTrip()
        {
            CheckParsingRoundTrip(new XmssParameters(4, NistObjectIdentifiers.IdSha256));
            CheckParsingRoundTrip(new XmssParameters(4, NistObjectIdentifiers.IdSha512));
            CheckParsingRoundTrip(new XmssParameters(4, NistObjectIdentifiers.IdShake256Len, 24));
        }

        /// <summary>
        /// An XMSS signature is a (4 + n + (len + h) * n)-byte string (RFC 8391 sec. 4.1.8), so a signature
        /// carrying trailing data - or a truncated one - is not a signature for these parameters.
        /// </summary>
        [Test]
        public void SignatureWrongSizeRejected()
        {
            XmssParameters p = new XmssParameters(10, NistObjectIdentifiers.IdSha256);
            byte[] sig = Assembled(p, 5).ToByteArray();

            Assert.AreEqual(4 + 32 + (67 + 10) * 32, sig.Length);

            byte[][] wrongSize = new byte[][]
            {
                Arrays.Append(sig, 0x2a),
                Arrays.CopyOfRange(sig, 0, sig.Length - 1),
                new byte[0]
            };

            for (int i = 0; i != wrongSize.Length; i++)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssSignature.Builder(p).WithSignature(wrongSize[i]).Build(),
                    "no exception on signature of wrong size: " + i);
                Assert.AreEqual("signature has wrong size", e.Message);
            }

            Assert.Throws<ArgumentNullException>(() => new XmssSignature.Builder(p).WithSignature(null));
        }

        /// <summary>
        /// The four index bytes are read as a signed int, so an encoding can name a leaf the tree does not have, or
        /// a negative one.
        /// </summary>
        [Test]
        public void SignatureIndexOutOfTreeRejected()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] sig = Assembled(p, 15).ToByteArray();

            Assert.AreEqual(15, new XmssSignature.Builder(p).WithSignature(sig).Build().Index);

            sig[3] = 16;
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssSignature.Builder(p).WithSignature(sig));
            Assert.AreEqual("index out of bounds", e.Message);

            sig[0] = 0x80;
            Assert.Throws<InvalidOperationException>(() => new XmssSignature.Builder(p).WithSignature(sig));
        }

        /// <summary>
        /// A WOTS+ signature made at a leaf, with the authentication path the BDS state holds for that leaf, leads
        /// the verifier back to the root the state computed.
        /// </summary>
        [Test]
        public void AuthenticationPathLeadsToRoot()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = BdsStateSerializationTests.Seed(p, 0x00);
            byte[] secretSeed = BdsStateSerializationTests.Seed(p, 0x80);
            byte[] digest = BdsStateSerializationTests.Seed(p, 0x33);

            Bds state = new Bds(p, publicSeed, secretSeed, new byte[32]);
            for (int index = 0; index < (1 << p.Height); index++)
            {
                WotsPlus wotsPlus = new WotsPlus(new WotsPlusParameters(p.TreeDigestOid, p.TreeDigestSize));
                byte[] otsAddress = XmssAddress.OtsHashAddress(0, 0, index);
                wotsPlus.ImportKeys(wotsPlus.GetWotsPlusSecretKey(secretSeed, otsAddress), publicSeed);

                XmssSignature sig = new XmssSignature.Builder(p)
                    .WithIndex(index)
                    .WithWotsPlusSignature(wotsPlus.Sign(digest, otsAddress))
                    .WithAuthPath(state.GetAuthenticationPath())
                    .Build();
                XmssSignature parsed = new XmssSignature.Builder(p).WithSignature(sig.GetEncoded()).Build();

                WotsPlus verifier = new WotsPlus(new WotsPlusParameters(p.TreeDigestOid, p.TreeDigestSize));
                verifier.ImportKeys(new byte[p.TreeDigestSize], publicSeed);
                XmssNode root = XmssVerifierUtilities.GetRootNodeFromSignature(verifier, p.Height, digest, parsed,
                    XmssAddress.OtsHashAddress(0, 0, index), index);

                Assert.AreEqual(p.Height, root.Height);
                Assert.IsTrue(Arrays.AreEqual(state.Root.GetValue(), root.GetValue()), "index " + index);

                byte[] other = Arrays.Clone(digest);
                other[0] ^= 1;
                XmssNode wrong = XmssVerifierUtilities.GetRootNodeFromSignature(verifier, p.Height, other, parsed,
                    XmssAddress.OtsHashAddress(0, 0, index), index);
                Assert.IsFalse(Arrays.AreEqual(state.Root.GetValue(), wrong.GetValue()), "index " + index);

                if (index < (1 << p.Height) - 1)
                {
                    state = state.GetNextState(publicSeed, secretSeed, new byte[32]);
                }
            }

            WotsPlus w = new WotsPlus(new WotsPlusParameters(p.TreeDigestOid, p.TreeDigestSize));
            Assert.Throws<ArgumentException>(() => XmssVerifierUtilities.GetRootNodeFromSignature(w, p.Height,
                new byte[31], new XmssSignature.Builder(p).Build(), new byte[32], 0));
        }

        private static void CheckParsingRoundTrip(XmssParameters p)
        {
            XmssSignature sig1 = Assembled(p, 9);
            byte[] encoded = sig1.ToByteArray();

            Assert.AreEqual(XmssSignature.EncodedSizeOf(p), encoded.Length);
            Assert.IsTrue(Arrays.AreEqual(encoded, sig1.GetEncoded()));

            XmssSignature sig2 = new XmssSignature.Builder(p).WithSignature(encoded).Build();

            Assert.AreEqual(9, sig2.Index);
            Assert.IsTrue(Arrays.AreEqual(sig1.GetRandom(), sig2.GetRandom()));
            Assert.AreEqual(p.Height, sig2.AuthPath.Count);
            Assert.IsTrue(Arrays.AreEqual(encoded, sig2.ToByteArray()));
        }

        /// <summary>A signature with every byte of it distinct enough to show where it went.</summary>
        internal static XmssSignature Assembled(XmssParameters p, int index)
        {
            int n = p.TreeDigestSize;
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
            return new XmssSignature.Builder(p)
                .WithIndex(index)
                .WithRandom(BdsStateSerializationTests.Seed(p, 0x55))
                .WithWotsPlusSignature(wotsPlusSignature)
                .WithAuthPath(authPath)
                .Build();
        }
    }
}
