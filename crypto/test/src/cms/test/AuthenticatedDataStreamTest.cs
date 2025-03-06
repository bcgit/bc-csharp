using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
	[Parallelizable(ParallelScope.All)]
	public class AuthenticatedDataStreamTest
	{
		private const string SignDN = "O=Bouncy Castle, C=AU";

		private static AsymmetricCipherKeyPair signKP;
//		private static X509Certificate signCert;
		//signCert = CmsTestUtil.MakeCertificate(_signKP, SignDN, _signKP, SignDN);

//		private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";

//		private static AsymmetricCipherKeyPair origKP;
		//origKP = CmsTestUtil.MakeKeyPair();
//		private static X509Certificate origCert;
		//origCert = CmsTestUtil.MakeCertificate(_origKP, OrigDN, _signKP, SignDN);

		private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";

		private static AsymmetricCipherKeyPair reciKP;
		private static X509Certificate reciCert;

		private static AsymmetricCipherKeyPair origECKP;
		private static AsymmetricCipherKeyPair reciECKP;
		private static X509Certificate reciECCert;

        private static AsymmetricCipherKeyPair OrigECKP =>
            CmsTestUtil.InitKP(ref origECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair ReciECKP =>
            CmsTestUtil.InitKP(ref reciECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

        private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
            () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciECCert => CmsTestUtil.InitCertificate(ref reciECCert,
            () => CmsTestUtil.MakeCertificate(ReciECKP, ReciDN, SignKP, SignDN));

        [Test]
		public void TestKeyTransDESede()
		{
            TryKeyTrans(Encoding.ASCII.GetBytes("Eric H. Echidna"), CmsEnvelopedGenerator.DesEde3Cbc);
            // force multiple octet-string
            TryKeyTrans(new byte[2500], CmsEnvelopedGenerator.DesEde3Cbc);
        }

		private void TryKeyTrans(byte[] data, string macAlg)
		{
			CmsAuthenticatedDataStreamGenerator adGen = new CmsAuthenticatedDataStreamGenerator();

			adGen.AddKeyTransRecipient(ReciCert);

			MemoryStream bOut = new MemoryStream();
			Stream aOut = adGen.Open(bOut, macAlg);
			aOut.Write(data, 0, data.Length);
			aOut.Close();

			CmsAuthenticatedDataParser ad = new CmsAuthenticatedDataParser(bOut.ToArray());

			RecipientInformationStore recipients = ad.GetRecipientInfos();

			Assert.AreEqual(ad.MacAlgOid, macAlg);

			var c = recipients.GetRecipients();

			Assert.AreEqual(1, c.Count);

			foreach (RecipientInformation recipient in c)
			{
				Assert.AreEqual(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.Id);
				Assert.True(recipient.RecipientID.Match(ReciCert));

				byte[] recData = recipient.GetContent(ReciKP.Private);

				Assert.IsTrue(Arrays.AreEqual(data, recData));
				Assert.IsTrue(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
			}
		}
	}
}