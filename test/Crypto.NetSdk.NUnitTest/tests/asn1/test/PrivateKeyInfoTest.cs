using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class PrivateKeyInfoTest
        : SimpleTest
    {
        private static readonly byte[] priv = Base64.Decode(
            "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

        private static readonly byte[] privWithPub = Base64.Decode(
            "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
            "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
            "Z9w7lshQhqowtrbLDFw4rXAxZuE=");

        public override string Name
        {
            get { return "PrivateKeyInfoTest"; }
        }

        public override void PerformTest()
        {
            PrivateKeyInfo privInfo1 = PrivateKeyInfo.GetInstance(priv);

            IsTrue(!privInfo1.HasPublicKey);

            PrivateKeyInfo privInfo2 = new PrivateKeyInfo(privInfo1.PrivateKeyAlgorithm, privInfo1.ParsePrivateKey());

            IsTrue("enc 1 failed", AreEqual(priv, privInfo2.GetEncoded()));

            privInfo1 = PrivateKeyInfo.GetInstance(privWithPub);

            IsTrue(privInfo1.HasPublicKey);

            privInfo2 = new PrivateKeyInfo(privInfo1.PrivateKeyAlgorithm, privInfo1.ParsePrivateKey(), privInfo1.Attributes, privInfo1.PublicKeyData.GetOctets());

            IsTrue("enc 2 failed", AreEqual(privWithPub, privInfo2.GetEncoded()));
        }

        public  static void RunMainTests(string[] args)
        {
            RunTest(new PrivateKeyInfoTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
