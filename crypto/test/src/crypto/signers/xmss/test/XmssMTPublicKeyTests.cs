using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>Test cases for XmssMTPublicKeyParameters class.</summary>
    [TestFixture]
    public class XmssMTPublicKeyTests
    {
        /// <summary>A generated key pair's public key reads back to a key that encodes the same.</summary>
        /// <remarks>
        /// Java goes through its XMSSMT test harness for the key pair and the import; the harness's generateKeys and
        /// importState are the generator and the two builders, which is what is used here.
        /// </remarks>
        [Test]
        public void TestPublicKeyParsingSha256()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();
            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            byte[] privateKey = ((XmssMTPrivateKeyParameters)kp.Private).GetEncoded();
            byte[] publicKey = ((XmssMTPublicKeyParameters)kp.Public).GetEncoded();

            XmssMTPrivateKeyParameters priv = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(privateKey).Build();
            XmssMTPublicKeyParameters pub = new XmssMTPublicKeyParameters.Builder(parameters)
                .WithPublicKey(publicKey).Build();

            Assert.IsTrue(Arrays.AreEqual(priv.GetRoot(), pub.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(priv.GetPublicSeed(), pub.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(publicKey, pub.GetEncoded()));
        }

        [Test]
        public void TestConstructor()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 4, new Sha256Digest());
            XmssMTPublicKeyParameters pk = new XmssMTPublicKeyParameters.Builder(parameters).Build();

            byte[] pkByte = pk.GetEncoded();
            /* check everything is 0 */
            for (int i = 5; i < pkByte.Length; i++)
            {
                Assert.AreEqual(0x00, pkByte[i]);
            }

            Assert.AreEqual(68, pkByte.Length);
        }

        /// <summary>
        /// The two lengths an encoding may have - the pre-RFC root || seed, and the four byte parameter set
        /// identifier in front of it - decode, keeping the identifier the encoding named, and every other length
        /// is refused. The identifier is the XMSS^MT one, not the XMSS one of the layer trees.
        /// </summary>
        [Test]
        public void PublicKeyEncodingLengths()
        {
            XmssMTParameters parameters = XmssMTParameters.LookupByOid(1);
            int n = parameters.TreeDigestSize;
            byte[] root = new byte[n];
            byte[] seed = new byte[n];
            Arrays.Fill(root, 0x11);
            Arrays.Fill(seed, 0x22);

            XmssMTPublicKeyParameters key = new XmssMTPublicKeyParameters.Builder(parameters).WithRoot(root)
                .WithPublicSeed(seed).Build();
            byte[] withOid = key.GetEncoded();
            Assert.AreEqual(4 + 2 * n, withOid.Length);
            Assert.AreEqual("00000001", Hex.ToHexString(withOid, 0, 4));

            byte[] withoutOid = Arrays.CopyOfRange(withOid, 4, withOid.Length);
            XmssMTPublicKeyParameters legacy = new XmssMTPublicKeyParameters.Builder(parameters)
                .WithPublicKey(withoutOid).Build();
            Assert.IsTrue(Arrays.AreEqual(root, legacy.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(seed, legacy.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(withoutOid, legacy.GetEncoded()));

            int[] wrongLengths = new int[]{ 0, 1, 2 * n - 1, 2 * n + 1, 4 + 2 * n - 1, 4 + 2 * n + 1 };
            foreach (int length in wrongLengths)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssMTPublicKeyParameters.Builder(parameters).WithPublicKey(new byte[length]).Build(),
                    "length " + length);
                Assert.AreEqual("public key has wrong size", e.Message);
            }
        }

        /// <summary>The accessors hand out copies, and the builder keeps copies of what it was given.</summary>
        [Test]
        public void PublicKeyFieldsAreCopied()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, new Sha256Digest());
            byte[] root = new byte[32];
            root[0] = 1;
            XmssMTPublicKeyParameters.Builder builder = new XmssMTPublicKeyParameters.Builder(parameters)
                .WithRoot(root);
            root[0] = 2;
            XmssMTPublicKeyParameters key = builder.Build();
            Assert.AreEqual(1, key.GetRoot()[0]);

            key.GetRoot()[0] = 3;
            key.GetPublicSeed()[0] = 3;
            Assert.AreEqual(1, key.GetRoot()[0]);
            Assert.AreEqual(0, key.GetPublicSeed()[0]);

            Assert.IsFalse(key.IsPrivate);
            Assert.AreSame(parameters, key.Parameters);
            Assert.AreEqual("SHA-256", key.TreeDigest);
        }
    }
}
