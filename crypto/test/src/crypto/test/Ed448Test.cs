using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
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

        public static void MainOld(string[] args)
        {
            RunTest(new Ed448Test());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public override void PerformTest()
        {
            for (int i = 0; i < 10; ++i)
            {
                byte[] context = RandomContext(Random.NextInt() & 255);
                DoTestConsistency(Ed448.Algorithm.Ed448, context);
                DoTestConsistency(Ed448.Algorithm.Ed448ph, context);
            }
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
                    throw new ArgumentException("algorithm");
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
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(msg, 0, msg.Length);
            bool shouldVerify = verifier.VerifySignature(signature);

            if (!shouldVerify)
            {
                Fail("Ed448(" + algorithm + ") signature failed to verify");
            }

            signature[Random.Next() % signature.Length] ^= (byte)(1 << (Random.NextInt() & 7));

            verifier.Init(false, publicKey);
            verifier.BlockUpdate(msg, 0, msg.Length);
            bool shouldNotVerify = verifier.VerifySignature(signature);

            if (shouldNotVerify)
            {
                Fail("Ed448(" + algorithm + ") bad signature incorrectly verified");
            }
        }
    }
}
