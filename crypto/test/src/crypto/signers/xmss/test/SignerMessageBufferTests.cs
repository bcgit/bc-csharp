using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// <see cref="XmssSigner.Init"/> and <see cref="XmssMTSigner.Init"/> start a fresh operation, so a message absorbed
    /// before it must not survive into the new one. A signer reused across operations would otherwise sign or verify
    /// the leftover bytes concatenated with the ones the caller actually presented - and on the signing side it would
    /// spend a one-time key doing so.
    /// </summary>
    [TestFixture]
    public class SignerMessageBufferTests
    {
        private const int Height = 4;
        private const int Layers = 2;

        private static readonly byte[] Leftover = new byte[]{ 0xde, 0xad, 0xbe, 0xef };
        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4, 5 };

        private static AsymmetricCipherKeyPair XmssKeyPair()
        {
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(Height,
                new Sha256Digest())));

            return kpg.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair XmssMTKeyPair()
        {
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), new XmssMTParameters(Height, Layers,
                new Sha256Digest())));

            return kpg.GenerateKeyPair();
        }

        private static bool Verifies(XmssMTSigner verifier, AsymmetricCipherKeyPair kp, byte[] message,
            byte[] signature)
        {
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(message, 0, message.Length);

            return verifier.VerifySignature(signature);
        }

        private static bool Verifies(XmssSigner verifier, AsymmetricCipherKeyPair kp, byte[] message,
            byte[] signature)
        {
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(message, 0, message.Length);

            return verifier.VerifySignature(signature);
        }

        /// <summary>
        /// Bytes absorbed after one signing init are discarded by the next one, so the signature covers the message
        /// presented after it and nothing else.
        /// </summary>
        [Test]
        public void TestInitDiscardsBufferedMessageBeforeSigning()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Leftover, 0, Leftover.Length);

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(Verifies(new XmssSigner(), kp, Message, signer.GenerateSignature()));

            AsymmetricCipherKeyPair mtKp = XmssMTKeyPair();
            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(true, mtKp.Private);
            mtSigner.BlockUpdate(Leftover, 0, Leftover.Length);

            mtSigner.Init(true, mtKp.Private);
            mtSigner.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(Verifies(new XmssMTSigner(), mtKp, Message, mtSigner.GenerateSignature()));
        }

        /// <summary>
        /// The same on the verification side: an abandoned verification leaves nothing behind for the next one,
        /// which would otherwise reject a perfectly good signature.
        /// </summary>
        [Test]
        public void TestInitDiscardsBufferedMessageBeforeVerifying()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);

            byte[] signature = signer.GenerateSignature();

            XmssSigner verifier = new XmssSigner();

            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(Leftover, 0, Leftover.Length);

            Assert.IsTrue(Verifies(verifier, kp, Message, signature));

            AsymmetricCipherKeyPair mtKp = XmssMTKeyPair();
            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(true, mtKp.Private);
            mtSigner.BlockUpdate(Message, 0, Message.Length);

            byte[] mtSignature = mtSigner.GenerateSignature();

            XmssMTSigner mtVerifier = new XmssMTSigner();

            mtVerifier.Init(false, mtKp.Public);
            mtVerifier.BlockUpdate(Leftover, 0, Leftover.Length);

            Assert.IsTrue(Verifies(mtVerifier, mtKp, Message, mtSignature));
        }

        /// <summary>
        /// The dangerous direction: bytes absorbed while verifying must not be carried into a signature. A signer
        /// that did so would spend a one-time key on a message its caller never presented.
        /// </summary>
        [Test]
        public void TestInitDiscardsBufferedMessageAcrossModeChange()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(false, kp.Public);
            signer.BlockUpdate(Leftover, 0, Leftover.Length);

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(Verifies(new XmssSigner(), kp, Message, signer.GenerateSignature()));

            AsymmetricCipherKeyPair mtKp = XmssMTKeyPair();
            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(false, mtKp.Public);
            mtSigner.BlockUpdate(Leftover, 0, Leftover.Length);

            mtSigner.Init(true, mtKp.Private);
            mtSigner.BlockUpdate(Message, 0, Message.Length);

            Assert.IsTrue(Verifies(new XmssMTSigner(), mtKp, Message, mtSigner.GenerateSignature()));
        }

        /// <summary>
        /// The compatibility half: Init() clearing the buffer must not disturb the ordinary case, where a signer is
        /// initialised once and the message arrives afterwards in several updates.
        /// </summary>
        [Test]
        public void TestMessageAbsorbedAfterInitIsSigned()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);
            signer.Update(Message[0]);
            signer.BlockUpdate(Message, 1, Message.Length - 1);

            Assert.IsTrue(Verifies(new XmssSigner(), kp, Message, signer.GenerateSignature()));

            AsymmetricCipherKeyPair mtKp = XmssMTKeyPair();
            XmssMTSigner mtSigner = new XmssMTSigner();

            mtSigner.Init(true, mtKp.Private);
            mtSigner.Update(Message[0]);
            mtSigner.BlockUpdate(Message, 1, Message.Length - 1);

            Assert.IsTrue(Verifies(new XmssMTSigner(), mtKp, Message, mtSigner.GenerateSignature()));
        }

        /// <summary>
        /// A verification that fails consumes the buffered message all the same, so the next one covers only what is
        /// presented after it; and Reset() discards what has been absorbed before a signature.
        /// </summary>
        [Test]
        public void FailureAndResetDiscardTheBufferedMessage()
        {
            AsymmetricCipherKeyPair kp = XmssKeyPair();
            XmssSigner signer = new XmssSigner();

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);
            byte[] signature = signer.GenerateSignature();

            XmssSigner verifier = new XmssSigner();
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(Leftover, 0, Leftover.Length);
            Assert.IsFalse(verifier.VerifySignature(signature));
            verifier.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(verifier.VerifySignature(signature));

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Leftover, 0, Leftover.Length);
            signer.Reset();
            signer.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(Verifies(new XmssSigner(), kp, Message, signer.GenerateSignature()));

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message.AsSpan(0, 2));
            signer.BlockUpdate(Message.AsSpan(2));
            Assert.IsTrue(Verifies(new XmssSigner(), kp, Message, signer.GenerateSignature()));
#endif
        }

        /// <summary>As <see cref="FailureAndResetDiscardTheBufferedMessage"/>, for the XMSS^MT signer.</summary>
        [Test]
        public void MTFailureAndResetDiscardTheBufferedMessage()
        {
            AsymmetricCipherKeyPair kp = XmssMTKeyPair();
            XmssMTSigner signer = new XmssMTSigner();

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message, 0, Message.Length);
            byte[] signature = signer.GenerateSignature();

            XmssMTSigner verifier = new XmssMTSigner();
            verifier.Init(false, kp.Public);
            verifier.BlockUpdate(Leftover, 0, Leftover.Length);
            Assert.IsFalse(verifier.VerifySignature(signature));
            verifier.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(verifier.VerifySignature(signature));

            signer.Init(true, kp.Private);
            signer.BlockUpdate(Leftover, 0, Leftover.Length);
            signer.Reset();
            signer.BlockUpdate(Message, 0, Message.Length);
            Assert.IsTrue(Verifies(new XmssMTSigner(), kp, Message, signer.GenerateSignature()));

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            signer.Init(true, kp.Private);
            signer.BlockUpdate(Message.AsSpan(0, 2));
            signer.BlockUpdate(Message.AsSpan(2));
            Assert.IsTrue(Verifies(new XmssMTSigner(), kp, Message, signer.GenerateSignature()));
#endif
        }
    }
}
