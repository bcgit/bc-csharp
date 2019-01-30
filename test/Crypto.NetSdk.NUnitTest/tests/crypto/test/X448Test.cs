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
    public class X448Test
        : SimpleTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public override string Name
        {
            get { return "X448"; }
        }

        public  static void RunMainTests(string[] args)
        {
            RunTest(new X448Test());
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
            IAsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
            kpGen.Init(new X448KeyGenerationParameters(Random));

            AsymmetricCipherKeyPair kpA = kpGen.GenerateKeyPair();
            AsymmetricCipherKeyPair kpB = kpGen.GenerateKeyPair();

            X448Agreement agreeA = new X448Agreement();
            agreeA.Init(kpA.Private);
            byte[] secretA = new byte[agreeA.AgreementSize];
            agreeA.CalculateAgreement(kpB.Public, secretA, 0);

            X448Agreement agreeB = new X448Agreement();
            agreeB.Init(kpB.Private);
            byte[] secretB = new byte[agreeB.AgreementSize];
            agreeB.CalculateAgreement(kpA.Public, secretB, 0);

            if (!AreEqual(secretA, secretB))
            {
                Fail("X448 agreement failed");
            }
        }
    }
}
