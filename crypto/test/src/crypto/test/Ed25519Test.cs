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
    public class Ed25519Test
        : SimpleTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public override string Name
        {
            get { return "Ed25519"; }
        }

        [Test]
        public void TestRegression_GitHub_bc_java_1599()
        {
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
                Hex.DecodeStrict("386e7cf7b9e8353933b07f1db8d84d3720bb667cbd811b312b4e338672338a6d"));
            byte[] content = Hex.DecodeStrict("414141624c6743596c6f414141514943486e6a4a71326a75705455472d5a36694d716871313467414854486f64757677694844664f594a3230775f77426c6e35444a3953614e616353496835336b626e716e723965ef34c5");
            byte[] sig = Hex.DecodeStrict("74dc43223fc21b9157e686a1446621a4640464b8ee4877ea7e3963cb5da8b21b9089241defdd7f36448ec4c76174af131994321da7e28483b3c2a7906947fa0f");

            ISigner signer = new Ed25519Signer();
            signer.Init(false, publicKey);
            signer.BlockUpdate(content, 0, content.Length);
            bool verified = signer.VerifySignature(sig);
            Assert.True(verified);
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
                DoTestConsistency(Ed25519.Algorithm.Ed25519, null);

                byte[] context = RandomContext(Random.NextInt() & 255);
                DoTestConsistency(Ed25519.Algorithm.Ed25519ctx, context);
                DoTestConsistency(Ed25519.Algorithm.Ed25519ph, context);
            }
        }

        private void BasicSigTest()
        {
            Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(
                Hex.DecodeStrict("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
                Hex.DecodeStrict("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

            byte[] sig = Hex.Decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

            ISigner signer = new Ed25519Signer();
            signer.Init(true, privateKey);

            IsTrue(AreEqual(sig, signer.GenerateSignature()));

            signer.Init(false, publicKey);

            IsTrue(signer.VerifySignature(sig));
        }

        private ISigner CreateSigner(Ed25519.Algorithm algorithm, byte[] context)
        {
            switch (algorithm)
            {
            case Ed25519.Algorithm.Ed25519:
                return new Ed25519Signer();
            case Ed25519.Algorithm.Ed25519ctx:
                return new Ed25519ctxSigner(context);
            case Ed25519.Algorithm.Ed25519ph:
                return new Ed25519phSigner(context);
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

        private void DoTestConsistency(Ed25519.Algorithm algorithm, byte[] context)
        {
            Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
            kpg.Init(new Ed25519KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters)kp.Private;
            Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters)kp.Public;

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
                    Fail("Ed25519(" + algorithm + ") signature failed to verify");
                }
            }

            {
                byte[] wrongLengthSignature = Arrays.Append(signature, 0x00);

                verifier.Init(false, publicKey);
                verifier.BlockUpdate(msg, 0, msg.Length);
                bool shouldNotVerify = verifier.VerifySignature(wrongLengthSignature);

                if (shouldNotVerify)
                {
                    Fail("Ed25519(" + algorithm + ") wrong length signature incorrectly verified");
                }
            }

            if (msg.Length > 0)
            {
                bool shouldNotVerify = verifier.VerifySignature(signature);

                if (shouldNotVerify)
                {
                    Fail("Ed25519(" + algorithm + ") wrong length failure did not reset verifier");
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
                    Fail("Ed25519(" + algorithm + ") bad signature incorrectly verified");
                }
            }
        }
    }
}
