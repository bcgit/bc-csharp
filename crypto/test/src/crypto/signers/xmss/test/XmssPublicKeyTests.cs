using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>Test cases for XmssPublicKeyParameters class.</summary>
    [TestFixture]
    public class XmssPublicKeyTests
    {
        [Test]
        public void TestPublicKeyParsingSha256()
        {
            XmssParameters parameters = new XmssParameters(10, new Sha256Digest());
            byte[] root = Hex.Decode("000102030405060708090a0b0c0d0e0f10203003405060708090a0b0c0d0e0f0");
            XmssPublicKeyParameters publicKey = new XmssPublicKeyParameters.Builder(parameters).WithRoot(root)
                .Build();

            byte[] export = publicKey.GetEncoded();

            XmssPublicKeyParameters publicKey2 = new XmssPublicKeyParameters.Builder(parameters)
                .WithPublicKey(export).Build();

            Assert.IsTrue(Arrays.AreEqual(publicKey.GetRoot(), publicKey2.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(publicKey.GetPublicSeed(), publicKey2.GetPublicSeed()));
        }

        [Test]
        public void TestPublicKeyParsingSha512()
        {
            XmssParameters parameters = new XmssParameters(10, new Sha512Digest());
            byte[] root = Hex.Decode("000102030405060708090a0b0c0d0e0f10203003405060708090a0b0c0d0e0f0"
                + "000102030405060708090a0b0c0d0e0f10203003405060708090a0b0c0d0e0f0");
            XmssPublicKeyParameters publicKey = new XmssPublicKeyParameters.Builder(parameters).WithRoot(root)
                .Build();

            byte[] export = publicKey.GetEncoded();

            XmssPublicKeyParameters publicKey2 = new XmssPublicKeyParameters.Builder(parameters)
                .WithPublicKey(export).Build();

            Assert.IsTrue(Arrays.AreEqual(publicKey.GetRoot(), publicKey2.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(publicKey.GetPublicSeed(), publicKey2.GetPublicSeed()));
        }

        /// <summary>
        /// An encoding naming one registered parameter set is refused under another, rather than read at the other's
        /// size and written back out under its own identifier. An encoding naming none is read as it always was.
        /// </summary>
        [Test]
        public void TestPublicKeyOfAnotherParameterSetRejected()
        {
            XmssParameters sha2_10 = XmssParameters.LookupByOid(1);
            XmssParameters sha2_16 = XmssParameters.LookupByOid(2);
            byte[] root = Hex.Decode("000102030405060708090a0b0c0d0e0f10203003405060708090a0b0c0d0e0f0");
            byte[] encoded = new XmssPublicKeyParameters.Builder(sha2_10).WithRoot(root).Build().GetEncoded();

            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPublicKeyParameters.Builder(sha2_16).WithPublicKey(encoded).Build());
            Assert.AreEqual("public key parameter set does not match the parameters", e.Message);

            byte[] noOid = Arrays.CopyOfRange(encoded, 4, encoded.Length);
            XmssPublicKeyParameters legacy = new XmssPublicKeyParameters.Builder(sha2_16).WithPublicKey(noOid).Build();
            Assert.IsTrue(Arrays.AreEqual(root, legacy.GetRoot()));
        }

        [Test]
        public void TestConstructor()
        {
            XmssParameters parameters = new XmssParameters(10, new Sha256Digest());
            XmssPublicKeyParameters pk = new XmssPublicKeyParameters.Builder(parameters).Build();

            byte[] pkByte = pk.GetEncoded();
            /* check everything is 0 */
            for (int i = 5; i < pkByte.Length; i++)
            {
                Assert.AreEqual(0x00, pkByte[i]);
            }
        }

        /// <summary>
        /// The two lengths an encoding may have - the pre-RFC root || seed, and the four byte parameter set
        /// identifier in front of it - decode, keeping the identifier the encoding named, and every other length
        /// is refused before anything is read out of it.
        /// </summary>
        [Test]
        public void PublicKeyEncodingLengths()
        {
            XmssParameters parameters = XmssParameters.LookupByOid(1);
            int n = parameters.TreeDigestSize;
            byte[] root = new byte[n];
            byte[] seed = new byte[n];
            Arrays.Fill(root, 0x11);
            Arrays.Fill(seed, 0x22);

            XmssPublicKeyParameters key = new XmssPublicKeyParameters.Builder(parameters).WithRoot(root)
                .WithPublicSeed(seed).Build();
            byte[] withOid = key.GetEncoded();
            Assert.AreEqual(4 + 2 * n, withOid.Length);
            Assert.AreEqual("00000001", Hex.ToHexString(withOid, 0, 4));

            byte[] withoutOid = Arrays.CopyOfRange(withOid, 4, withOid.Length);
            XmssPublicKeyParameters legacy = new XmssPublicKeyParameters.Builder(parameters)
                .WithPublicKey(withoutOid).Build();
            Assert.IsTrue(Arrays.AreEqual(root, legacy.GetRoot()));
            Assert.IsTrue(Arrays.AreEqual(seed, legacy.GetPublicSeed()));
            // a key read without an identifier is written back without one
            Assert.IsTrue(Arrays.AreEqual(withoutOid, legacy.GetEncoded()));

            XmssPublicKeyParameters decoded = new XmssPublicKeyParameters.Builder(parameters)
                .WithPublicKey(withOid).Build();
            Assert.IsTrue(Arrays.AreEqual(withOid, decoded.GetEncoded()));

            int[] wrongLengths = new int[]{ 0, 1, 2 * n - 1, 2 * n + 1, 4 + 2 * n - 1, 4 + 2 * n + 1 };
            foreach (int length in wrongLengths)
            {
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPublicKeyParameters.Builder(parameters).WithPublicKey(new byte[length]).Build(),
                    "length " + length);
                Assert.AreEqual("public key has wrong size", e.Message);
            }
        }

        /// <summary>The accessors hand out copies, and the builder keeps copies of what it was given.</summary>
        [Test]
        public void PublicKeyFieldsAreCopied()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            byte[] root = new byte[32];
            root[0] = 1;
            XmssPublicKeyParameters.Builder builder = new XmssPublicKeyParameters.Builder(parameters).WithRoot(root);
            root[0] = 2;
            XmssPublicKeyParameters key = builder.Build();
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
