using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class Ed448Test
        : SimpleTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public override string Name
        {
            get { return "Ed448"; }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public override void PerformTest()
        {
            BasicSigTest();

            for (int i = 0; i < 10; ++i)
            {
                byte[] context = RandomContext(Random.NextInt() & 255);
                DoTestConsistency(Ed448.Algorithm.Ed448, context);
                DoTestConsistency(Ed448.Algorithm.Ed448ph, context);
            }
        }

        private void BasicSigTest()
        {
            Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(
                Hex.DecodeStrict(
                    "6c82a562cb808d10d632be89c8513ebf" +
                    "6c929f34ddfa8c9f63c9960ef6e348a3" +
                    "528c8a3fcc2f044e39a3fc5b94492f8f" +
                    "032e7549a20098f95b"));
            Ed448PublicKeyParameters publicKey = new Ed448PublicKeyParameters(
                Hex.DecodeStrict("5fd7449b59b461fd2ce787ec616ad46a" +
                    "1da1342485a70e1f8a0ea75d80e96778" +
                    "edf124769b46c7061bd6783df1e50f6c" +
                    "d1fa1abeafe8256180"));

            byte[] sig = Hex.DecodeStrict("533a37f6bbe457251f023c0d88f976ae" +
                "2dfb504a843e34d2074fd823d41a591f" +
                "2b233f034f628281f2fd7a22ddd47d78" +
                "28c59bd0a21bfd3980ff0d2028d4b18a" +
                "9df63e006c5d1c2d345b925d8dc00b41" +
                "04852db99ac5c7cdda8530a113a0f4db" +
                "b61149f05a7363268c71d95808ff2e65" +
                "2600");

            ISigner signer = new Ed448Signer(new byte[0]);
            signer.Init(true, privateKey);

            IsTrue(AreEqual(sig, signer.GenerateSignature()));

            signer.Init(false, publicKey);

            IsTrue(signer.VerifySignature(sig));
        }

        private ISigner CreateSigner(Ed448.Algorithm algorithm, byte[] context)
        {
            switch (algorithm)
            {
            case Ed448.Algorithm.Ed448:
                return new Ed448Signer(context);
            case Ed448.Algorithm.Ed448ph:
                return new Ed448phSigner(context);
            default:
                throw new ArgumentException(nameof(algorithm));
            }
        }

        private byte[] RandomContext(int length)
        {
            byte[] context = new byte[length];
            Random.NextBytes(context);
            return context;
        }

        private void DoTestConsistency(Ed448.Algorithm algorithm, byte[] context)
        {
            Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
            kpg.Init(new Ed448KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)kp.Private;
            Ed448PublicKeyParameters publicKey = (Ed448PublicKeyParameters)kp.Public;

            byte[] msg = new byte[Random.NextInt() & 255];
            Random.NextBytes(msg);

            ISigner signer = CreateSigner(algorithm, context);
            signer.Init(true, privateKey);
            signer.BlockUpdate(msg, 0, msg.Length);
            byte[] signature = signer.GenerateSignature();

            ISigner verifier = CreateSigner(algorithm, context);

            {
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(msg, 0, msg.Length);
                bool shouldVerify = verifier.VerifySignature(signature);

                if (!shouldVerify)
                {
                    Fail("Ed448(" + algorithm + ") signature failed to verify");
                }
            }

            {
                byte[] wrongLengthSignature = Arrays.Append(signature, 0x00);

                verifier.Init(false, publicKey);
                verifier.BlockUpdate(msg, 0, msg.Length);
                bool shouldNotVerify = verifier.VerifySignature(wrongLengthSignature);

                if (shouldNotVerify)
                {
                    Fail("Ed448(" + algorithm + ") wrong length signature incorrectly verified");
                }
            }

            if (msg.Length > 0)
            {
                bool shouldNotVerify = verifier.VerifySignature(signature);

                if (shouldNotVerify)
                {
                    Fail("Ed448(" + algorithm + ") wrong length failure did not reset verifier");
                }
            }

            {
                byte[] badSignature = Arrays.Clone(signature);
                badSignature[Random.Next() % badSignature.Length] ^= (byte)(1 << (Random.NextInt() & 7));

                verifier.Init(false, publicKey);
                verifier.BlockUpdate(msg, 0, msg.Length);
                bool shouldNotVerify = verifier.VerifySignature(badSignature);

                if (shouldNotVerify)
                {
                    Fail("Ed448(" + algorithm + ") bad signature incorrectly verified");
                }
            }
        }
    }
}
