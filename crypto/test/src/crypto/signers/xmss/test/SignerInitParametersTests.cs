using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// <see cref="XmssSigner.Init"/> takes a key wrapped in <see cref="ParametersWithRandom"/> on either side. The
    /// random is discarded in both cases, so a signature taken through the wrapper is the one the bare key would
    /// have made.
    /// </summary>
    /// <remarks>The XMSS^MT method arrives with the XMSS^MT signer.</remarks>
    [TestFixture]
    public class SignerInitParametersTests
    {
        private const int Height = 4;

        [Test]
        public void TestXmssTakesAWrappedKeyOnEitherSide()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(Height,
                new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, new ParametersWithRandom(kp.Private, new SecureRandom()));
            signer.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

            byte[] signature = signer.GenerateSignature();

            XmssSigner verifier = new XmssSigner();

            verifier.Init(false, new ParametersWithRandom(kp.Public, new SecureRandom()));
            verifier.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

            Assert.IsTrue(verifier.VerifySignature(signature));

            // the bare key still initialises, and says the wrapper changed nothing about the signature
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(new byte[]{ 1, 2, 3 }, 0, 3);

            Assert.IsTrue(verifier.VerifySignature(signature));
        }

        /// <summary>
        /// A key of the wrong kind, or none, is refused before anything about the signer changes: a signer that was
        /// initialised for signing goes on signing with the key it had.
        /// </summary>
        [Test]
        public void WrongKeyRefusedWithoutDisturbingTheSigner()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(Height,
                new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);

            Assert.Throws<InvalidCastException>(() => signer.Init(true, kp.Public));
            Assert.Throws<InvalidCastException>(() => signer.Init(false, kp.Private));
            Assert.Throws<ArgumentNullException>(() => signer.Init(true, null));
            Assert.Throws<ArgumentNullException>(() => signer.Init(false, null));

            Assert.AreEqual("XMSS", signer.AlgorithmName);
            Assert.AreEqual(1 << Height, signer.GetUsagesRemaining());
            byte[] signature = XmssHarnessTests.Sign(signer, new byte[]{ 1, 2, 3 });
            Assert.AreEqual(signer.GetMaxSignatureSize(), signature.Length);

            signer.Init(false, kp.Public);
            Assert.AreEqual(signature.Length, signer.GetMaxSignatureSize());
            Assert.IsTrue(XmssHarnessTests.Verify(signer, new byte[]{ 1, 2, 3 }, signature));

            Assert.Throws<InvalidOperationException>(() => new XmssSigner().GetMaxSignatureSize());
        }
    }
}
