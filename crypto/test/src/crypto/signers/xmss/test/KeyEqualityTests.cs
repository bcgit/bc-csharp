using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>What a stateful private key's Equals() and GetHashCode() answer.</summary>
    /// <remarks>
    /// <para>
    /// Two keys of a key pair differ in where they have got to and in nothing else, so Equals() has to answer on the
    /// index while GetHashCode() must not - it is over the fields that do not move as the key signs, so keys from one
    /// key pair share a bucket of a set or a dictionary and are told apart inside it.
    /// </para>
    /// <para>
    /// testXmssMtSignatureMovesTheAnswerNotTheBucket arrives with the XMSS^MT signer.
    /// <see cref="RollMovesTheAnswerNotTheBucket"/> asserts the property of
    /// <see cref="TestXmssSignatureMovesTheAnswerNotTheBucket"/> through RollKey().
    /// </para>
    /// </remarks>
    [TestFixture]
    public class KeyEqualityTests
    {
        private const int Height = 4;
        private const int Layers = 2;

        private static byte[] Filled(byte b, int n)
        {
            byte[] rv = new byte[n];

            for (int i = 0; i != n; i++)
            {
                rv[i] = b;
            }

            return rv;
        }

        /// <summary>The root the seeds compute, which a key built from them must declare.</summary>
        private static byte[] RootOf(XmssParameters parameters, byte[] secretKeySeed, byte[] publicSeed) =>
            new Bds(parameters, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0)).Root.GetValue();

        private static XmssPrivateKeyParameters NewXmssKey()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(),
                new XmssParameters(Height, new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            return (XmssPrivateKeyParameters)kp.Private;
        }

        private static XmssMTPrivateKeyParameters NewXmssMtKey()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(Height, Layers, new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            return (XmssMTPrivateKeyParameters)kp.Private;
        }

        private static XmssPrivateKeyParameters DecodeXmss(XmssPrivateKeyParameters key, byte[] enc) =>
            new XmssPrivateKeyParameters.Builder(key.Parameters).WithPrivateKey(enc).Build();

        private static XmssMTPrivateKeyParameters DecodeXmssMt(XmssMTPrivateKeyParameters key, byte[] enc) =>
            new XmssMTPrivateKeyParameters.Builder(key.Parameters).WithPrivateKey(enc).Build();

        /// <summary>
        /// Two keys decoded from one encoding are two objects the same key, so they answer equal and hash the same.
        /// </summary>
        [Test]
        public void TestXmssDecodedCopiesAgree()
        {
            XmssPrivateKeyParameters key = NewXmssKey();
            byte[] enc = key.GetEncoded();

            XmssPrivateKeyParameters a = DecodeXmss(key, enc);
            XmssPrivateKeyParameters b = DecodeXmss(key, enc);

            Assert.IsFalse(a == b, "two distinct objects wanted");
            Assert.AreEqual(a, b);
            Assert.AreEqual(b, a);
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
            Assert.AreEqual(key, a);
            Assert.AreEqual(key.GetHashCode(), a.GetHashCode());
        }

        [Test]
        public void TestXmssMtDecodedCopiesAgree()
        {
            XmssMTPrivateKeyParameters key = NewXmssMtKey();
            byte[] enc = key.GetEncoded();

            XmssMTPrivateKeyParameters a = DecodeXmssMt(key, enc);
            XmssMTPrivateKeyParameters b = DecodeXmssMt(key, enc);

            Assert.IsFalse(a == b, "two distinct objects wanted");
            Assert.AreEqual(a, b);
            Assert.AreEqual(b, a);
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
            Assert.AreEqual(key, a);
            Assert.AreEqual(key.GetHashCode(), a.GetHashCode());
        }

        /// <summary>
        /// Keys of two key pairs are told apart, and land in different buckets. The two are built from fixed
        /// material differing in one field rather than generated, so the hash comparison decides something every
        /// run.
        /// </summary>
        [Test]
        public void TestXmssPublicMaterialDecidesTheBucket()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            int n = parameters.TreeDigestSize;

            // a root the seeds do not compute is refused, except on a spent key, which carries no tree to compare
            // it with: the two keys are built there so that they can differ in the root alone
            XmssPrivateKeyParameters a = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(Filled(4, n)).WithIndex(1 << Height).Build();

            XmssPrivateKeyParameters b = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(Filled(5, n)).WithIndex(1 << Height).Build();

            Assert.IsFalse(a.Equals(b), "keys differing in their root are not equal");
            Assert.IsFalse(a.GetHashCode() == b.GetHashCode(), "the root has to reach the hash");
        }

        [Test]
        public void TestXmssMtPublicMaterialDecidesTheBucket()
        {
            XmssMTParameters parameters = new XmssMTParameters(Height, Layers, new Sha256Digest());
            int n = parameters.TreeDigestSize;

            // as on the XMSS side, on a spent key, the one place a root the seeds do not compute is not refused
            long spent = 1L << parameters.Height;
            XmssMTPrivateKeyParameters a = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(Filled(4, n)).WithIndex(spent).Build();

            XmssMTPrivateKeyParameters b = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(Filled(5, n)).WithIndex(spent).Build();

            Assert.IsFalse(a.Equals(b), "keys differing in their root are not equal");
            Assert.IsFalse(a.GetHashCode() == b.GetHashCode(), "the root has to reach the hash");
        }

        /// <summary>
        /// The rest of the contract: a key is equal to itself, and to nothing that is not one of these keys. An XMSS
        /// key and an XMSS^MT key are never equal, whatever they hold.
        /// </summary>
        [Test]
        public void TestForeignObjects()
        {
            XmssPrivateKeyParameters xmss = NewXmssKey();
            XmssMTPrivateKeyParameters xmssMt = NewXmssMtKey();

            Assert.AreEqual(xmss, xmss);
            Assert.AreEqual(xmssMt, xmssMt);

            Assert.IsFalse(xmss.Equals(null));
            Assert.IsFalse(xmssMt.Equals(null));
            Assert.IsFalse(xmss.Equals("not a key"));
            Assert.IsFalse(xmssMt.Equals("not a key"));
            Assert.IsFalse(xmss.Equals(xmssMt));
            Assert.IsFalse(xmssMt.Equals(xmss));
        }

        /// <summary>
        /// A signature moves the answer Equals() gives and leaves the bucket GetHashCode() picks alone. The key at the
        /// earlier index is decoded from an encoding taken before signing rather than held as a reference, because
        /// RollKey() advances the key in place and hands back the same object.
        /// </summary>
        [Test]
        public void TestXmssSignatureMovesTheAnswerNotTheBucket()
        {
            XmssPrivateKeyParameters key = NewXmssKey();
            XmssPrivateKeyParameters before = DecodeXmss(key, key.GetEncoded());

            XmssSigner signer = new XmssSigner();

            signer.Init(true, key);
            signer.BlockUpdate(new byte[]{ 0x5a }, 0, 1);
            signer.GenerateSignature();

            XmssPrivateKeyParameters after = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();

            Assert.AreEqual(before.Index + 1, after.Index);
            Assert.IsFalse(before.Equals(after), "keys at different indices are not equal");
            Assert.IsFalse(after.Equals(before), "keys at different indices are not equal");
            Assert.AreEqual(before.GetHashCode(), after.GetHashCode(), "a signature must not move the key's bucket");
        }

        /// <summary>
        /// As <see cref="TestXmssSignatureMovesTheAnswerNotTheBucket"/>, with RollKey() moving the key instead of a
        /// signature.
        /// </summary>
        [Test]
        public void RollMovesTheAnswerNotTheBucket()
        {
            XmssPrivateKeyParameters key = NewXmssKey();
            XmssPrivateKeyParameters before = DecodeXmss(key, key.GetEncoded());

            XmssPrivateKeyParameters after = key.RollKey();

            Assert.AreSame(key, after, "RollKey() advances the key in place");
            Assert.AreEqual(before.Index + 1, after.Index);
            Assert.IsFalse(before.Equals(after), "keys at different indices are not equal");
            Assert.IsFalse(after.Equals(before), "keys at different indices are not equal");
            Assert.AreEqual(before.GetHashCode(), after.GetHashCode(), "a roll must not move the key's bucket");
        }

        /// <summary>As <see cref="RollMovesTheAnswerNotTheBucket"/>, for an XMSS^MT key.</summary>
        [Test]
        public void MtRollMovesTheAnswerNotTheBucket()
        {
            XmssMTPrivateKeyParameters key = NewXmssMtKey();
            XmssMTPrivateKeyParameters before = DecodeXmssMt(key, key.GetEncoded());

            XmssMTPrivateKeyParameters after = key.RollKey();

            Assert.AreSame(key, after, "RollKey() advances the key in place");
            Assert.AreEqual(before.Index + 1, after.Index);
            Assert.IsFalse(before.Equals(after), "keys at different indices are not equal");
            Assert.IsFalse(after.Equals(before), "keys at different indices are not equal");
            Assert.AreEqual(before.GetHashCode(), after.GetHashCode(), "a roll must not move the key's bucket");
        }

        /// <summary>The secret seeds take part in the answer, though not in the hash.</summary>
        [Test]
        public void SecretMaterialDecidesTheAnswer()
        {
            XmssParameters parameters = new XmssParameters(Height, new Sha256Digest());
            int n = parameters.TreeDigestSize;
            byte[] root = RootOf(parameters, Filled(1, n), Filled(3, n));

            XmssPrivateKeyParameters a = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(root).Build();

            XmssPrivateKeyParameters prf = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(6, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(root).Build();

            Assert.IsFalse(a.Equals(prf));
            Assert.AreEqual(a.GetHashCode(), prf.GetHashCode());

            XmssPrivateKeyParameters same = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(Filled(1, n)).WithSecretKeyPrf(Filled(2, n))
                .WithPublicSeed(Filled(3, n)).WithRoot(root).Build();

            Assert.IsTrue(a.Equals(same));
        }
    }
}
