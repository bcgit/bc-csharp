using System.Collections.Generic;
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
        private static X509Certificate signCert;

        private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";

        private static AsymmetricCipherKeyPair origKP;
        private static X509Certificate origCert;

        private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";

        private static AsymmetricCipherKeyPair reciKP;
        private static X509Certificate reciCert;

        private static AsymmetricCipherKeyPair origECKP;
        private static AsymmetricCipherKeyPair reciECKP;
        private static X509Certificate reciECCert;

        private static AsymmetricCipherKeyPair OrigECKP =>
            CmsTestUtil.InitKP(ref origECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair OrigKP =>
            CmsTestUtil.InitKP(ref origKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair ReciECKP =>
            CmsTestUtil.InitKP(ref reciECKP, CmsTestUtil.MakeECDsaKeyPair);

        private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

        private static X509Certificate OrigCert => CmsTestUtil.InitCertificate(ref origCert,
            () => CmsTestUtil.MakeCertificate(OrigKP, OrigDN, SignKP, SignDN));

        private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
            () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

        private static X509Certificate ReciECCert => CmsTestUtil.InitCertificate(ref reciECCert,
            () => CmsTestUtil.MakeCertificate(ReciECKP, ReciDN, SignKP, SignDN));

        private static X509Certificate SignCert => CmsTestUtil.InitCertificate(ref signCert,
            () => CmsTestUtil.MakeCertificate(SignKP, SignDN, SignKP, SignDN));

        [Test]
        public void TestKeyTransDESede()
        {
            TryKeyTrans(Encoding.ASCII.GetBytes("Eric H. Echidna"), CmsEnvelopedGenerator.DesEde3Cbc);
            // force multiple octet-string
            TryKeyTrans(new byte[2500], CmsEnvelopedGenerator.DesEde3Cbc);
        }

        [Test]
        public void OriginatorInfo()
        {
            byte[] data = Encoding.ASCII.GetBytes("Eric H. Echidna");

            CmsAuthenticatedDataStreamGenerator adGen = new CmsAuthenticatedDataStreamGenerator();

            adGen.AddKeyTransRecipient(ReciCert);

            adGen.OriginatorInformation = new OriginatorInformation(new OriginatorInfoGenerator(OrigCert).Generate());

            MemoryStream bOut = new MemoryStream();
            using (Stream aOut = adGen.Open(bOut, CmsEnvelopedGenerator.DesEde3Cbc))
            {
                aOut.Write(data, 0, data.Length);
            }

            CmsAuthenticatedDataParser ad = new CmsAuthenticatedDataParser(bOut.ToArray());

            var originatorCerts = new List<X509Certificate>(
                ad.OriginatorInformation.GetCertificates().EnumerateMatches(null));
            Assert.True(originatorCerts.Contains(OrigCert));

            RecipientInformationStore recipients = ad.GetRecipientInfos();

            Assert.AreEqual(CmsEnvelopedGenerator.DesEde3Cbc, ad.MacAlgOid);

            var c = recipients.GetRecipients();

            Assert.AreEqual(1, c.Count);

            foreach (RecipientInformation recipient in c)
            {
                Assert.AreEqual(recipient.KeyEncryptionAlgOid, PkcsObjectIdentifiers.RsaEncryption.GetID());
                Assert.True(recipient.RecipientID.Match(ReciCert));

                byte[] recData = recipient.GetContent(ReciKP.Private);

                Assert.That(Arrays.AreEqual(data, recData));
                Assert.That(Arrays.AreEqual(ad.GetMac(), recipient.GetMac()));
            }
        }

        private void TryKeyTrans(byte[] data, string macAlg)
        {
            CmsAuthenticatedDataStreamGenerator adGen = new CmsAuthenticatedDataStreamGenerator();

            adGen.AddKeyTransRecipient(ReciCert);

            MemoryStream bOut = new MemoryStream();
            using (Stream aOut = adGen.Open(bOut, macAlg))
            {
                aOut.Write(data, 0, data.Length);
            }

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
