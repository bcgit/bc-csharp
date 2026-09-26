using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <remarks>
    /// Test vectors were copied from
    /// https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
    /// </remarks>
    [TestFixture]
    public class ConcatenationKdfTest
    {
        [Test]
        public void KdfPositiveLenTest()
        {
            string sharedSecret = "e65b1905878b95f68b5535bd3b2b1013";
            string otherInfo = "830221b1730d9176f807d407";
            byte[] sharedSecretBytes = Hex.DecodeStrict(sharedSecret);
            byte[] otherInfoBytes = Hex.DecodeStrict(otherInfo);
            byte[] output = new byte[2048];

            ConcatenationKdfGenerator kdf = new ConcatenationKdfGenerator(new Sha512Digest());
            kdf.Init(new KdfParameters(sharedSecretBytes, otherInfoBytes));
            try
            {
                kdf.GenerateBytes(output, 0, 0);
                Assert.Fail("ConcatenationKDF must ignore the len parameter with value zero");
            }
            catch (ArgumentException iae)
            {
                Assert.That(iae.Message.StartsWith("must be > 0"), "Expect valid ConcatenationKDF error message");
            }

            try
            {
                kdf.GenerateBytes(output, 0, -1);
                Assert.Fail("ConcatenationKDF must ignore the len parameter with negative value");
            }
            catch (ArgumentException iae)
            {
                Assert.That(iae.Message.StartsWith("must be > 0"), "Expect valid ConcatenationKDF error message");
            }
        }

        /// <summary>
        /// The OtherInfo is optional in KDFParameters: a null one has to derive what an empty one does,
        /// H(counter || Z), on both the single-block and multi-block paths.
        /// </summary>
        [Test]
        public void NullOtherInfoTest()
        {
            byte[] sharedSecretBytes = Hex.DecodeStrict("3f892bd8b84dae64a782a35f6eaa8f00");
            ConcatenationKdfGenerator kdf = new ConcatenationKdfGenerator(new Sha256Digest());

            for (int len = 1; len <= 3 * 32 + 1; ++len)
            {
                byte[] withNull = new byte[len];
                byte[] withEmpty = new byte[len];

                kdf.Init(new KdfParameters(sharedSecretBytes, null));
                kdf.GenerateBytes(withNull, 0, len);

                kdf.Init(new KdfParameters(sharedSecretBytes, new byte[0]));
                kdf.GenerateBytes(withEmpty, 0, len);

                if (!Arrays.AreEqual(withNull, withEmpty))
                {
                    Assert.Fail("ConcatenationKDF with null OtherInfo differs from empty OtherInfo for len " + len);
                }
            }

            IDigest digest = new Sha256Digest();
            byte[] block1 = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(new byte[]{ 0, 0, 0, 1 }, 0, 4);
            digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length);
            digest.DoFinal(block1, 0);

            byte[] output = new byte[block1.Length];
            kdf.Init(new KdfParameters(sharedSecretBytes, null));
            kdf.GenerateBytes(output, 0, output.Length);

            if (!Arrays.AreEqual(block1, output))
            {
                Assert.Fail("ConcatenationKDF with null OtherInfo is not H(counter || Z)");
            }
        }

        [Test]
        public void Sha1()
        {
            string sharedSecret = "ebe28edbae5a410b87a479243db3f690";
            string otherInfo = "e60dd8b28228ce5b9be74d3b";
            string expected = "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d480d9192";

            ImplKdfTest(new Sha1Digest(), sharedSecret, otherInfo, expected);
        }

        [Test]
        public void Sha256()
        {
            string sharedSecret = "3f892bd8b84dae64a782a35f6eaa8f00";
            string otherInfo = "ec3f1cd873d28858a58cc39e";
            string expected = "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c714fa0";

            ImplKdfTest(new Sha256Digest(), sharedSecret, otherInfo, expected);
        }

        [Test]
        public void Sha512()
        {
            string sharedSecret = "e65b1905878b95f68b5535bd3b2b1013";
            string otherInfo = "830221b1730d9176f807d407";
            string expected = "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe318cabd9";

            ImplKdfTest(new Sha512Digest(), sharedSecret, otherInfo, expected);
        }

        private void ImplKdfTest(IDigest digest, string sharedSecret, string otherInfo, string expected)
        {
            byte[] sharedSecretBytes = Hex.DecodeStrict(sharedSecret);
            byte[] otherInfoBytes = Hex.DecodeStrict(otherInfo);
            byte[] expectedBytes = Hex.DecodeStrict(expected);
            byte[] output = new byte[15 + expectedBytes.Length];

            Random random = new Random();
            ConcatenationKdfGenerator kdf = new ConcatenationKdfGenerator(digest);

            for (int count = 1; count <= expectedBytes.Length; ++count)
            {
                Arrays.Fill(output, 0);
                int outputPos = random.Next(16); 

                kdf.Init(new KdfParameters(sharedSecretBytes, otherInfoBytes));
                kdf.GenerateBytes(output, outputPos, count);

                Assert.IsTrue(Arrays.AreEqual(expectedBytes, 0, count, output, outputPos, outputPos + count),
                    "ConcatenationKDF (" + digest.AlgorithmName + ") failed for count of " + count);
            }
        }
    }
}
