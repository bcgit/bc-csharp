using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	[TestFixture]
	public class X25519Test
		: SimpleTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public override string Name
        {
            get { return "X25519"; }
        }

        public static void Main(string[] args)
        {
            RunTest(new X25519Test());
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
                DoTestAgreement();
            }
        }

        private void DoTestAgreement()
        {
            IAsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kpA = kpGen.GenerateKeyPair();
            AsymmetricCipherKeyPair kpB = kpGen.GenerateKeyPair();

            X25519Agreement agreeA = new X25519Agreement();
            agreeA.Init(kpA.Private);
            byte[] secretA = new byte[agreeA.AgreementSize];
            agreeA.CalculateAgreement(kpB.Public, secretA, 0);

            X25519Agreement agreeB = new X25519Agreement();
            agreeB.Init(kpB.Private);
            byte[] secretB = new byte[agreeB.AgreementSize];
            agreeB.CalculateAgreement(kpA.Public, secretB, 0);

            if (!AreEqual(secretA, secretB))
            {
                Fail("X25519 agreement failed");
            }
        }
    }
}
