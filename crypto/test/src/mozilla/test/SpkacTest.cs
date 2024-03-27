using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Mozilla.Tests
{
    [TestFixture]
    public class SpkacTest
    {
        private static readonly byte[] Spkac = Base64.Decode(
            "MIIBOjCBpDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApne7ti0ibPhV8Iht" +
            "7Pws5iRckM7x4mtZYxEpeX5/IO8tDsBFdY86ewuY2f2KCca0oMWr43kdkZbPyzf4" +
            "CSV+0fZm9MJyNMywygZjoOCC+rS8kr0Ef31iHChhYsyejJnjw116Jnn96syhdHY6" +
            "lVD1rK0nn5ZkHjxU74gjoZu6BJMCAwEAARYAMA0GCSqGSIb3DQEBBAUAA4GBAKFL" +
            "g/luv0C7gMTI8ZKfFoSyi7Q7kiSQcmSj1WJgT56ouIRJO5NdvB/1n4GNik8VOAU0" +
            "NRztvGy3ZGqgbSav7lrxcNEvXH+dLbtS97s7yiaozpsOcEHqsBribpLOTRzYa8ci" +
            "CwkPmIiYqcby11diKLpd+W9RFYNme2v0rrbM2CyV");

        [Test]
        public void TestSpkac()
        {
            var spkac = new SignedPublicKeyAndChallenge(Spkac);

            var reencoded = spkac.ToAsn1Structure().GetEncoded(Asn1Encodable.Der);
            Assert.True(Arrays.AreEqual(Spkac, reencoded));

            var publicKey = spkac.GetPublicKey();
            var shouldVerify = spkac.IsSignatureValid(publicKey);
            Assert.True(shouldVerify);
        }
    }
}
