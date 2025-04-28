using System;
using System.Collections.Generic;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp.Tests
{
    [TestFixture]
    public class ProtectedMessageTest
    {
        private static AsymmetricCipherKeyPair _rsaKeyPair;

        private static AsymmetricCipherKeyPair RsaKeyPair =>
            SimpleTest.EnsureSingletonInitialized(ref _rsaKeyPair, CreateRsaKeyPair);

        [Test]
        public void TestProtectedMessage()
        {
            var kp = RsaKeyPair;
            var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

            var sender = new GeneralName(new X509Name("CN=Sender"));
            var recipient = new GeneralName(new X509Name("CN=Recip"));

            var certRepMessage = CertRepMessage.GetInstance(DerSequence.FromElement(new DerSequence()));

            var signatureFactory = new Asn1SignatureFactory("MD5withRSA", kp.Private);

            ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
                .SetBody(new PkiBody(PkiBody.TYPE_INIT_REP, certRepMessage))
                .AddCmpCertificate(cert)
                .Build(signatureFactory);

            Assert.True(message.Verify(kp.Public), "PkiMessage must verify (MD5withRSA)");

            Assert.AreEqual(sender, message.Header.Sender);
            Assert.AreEqual(recipient, message.Header.Recipient);
        }

        [Test]
        public void TestMacProtectedMessage()
        {
            var kp = RsaKeyPair;
            var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

            var sender = new GeneralName(new X509Name("CN=Sender"));
            var recipient = new GeneralName(new X509Name("CN=Recip"));

            var certRepMessage = CertRepMessage.GetInstance(DerSequence.FromElement(new DerSequence()));

            var macFactory = new PKMacBuilder().Build("testpass".ToCharArray());

            ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
                .SetBody(new PkiBody(PkiBody.TYPE_INIT_REP, certRepMessage))
                .AddCmpCertificate(cert)
                .Build(macFactory);

            Assert.True(message.Verify(new PKMacBuilder(), "testpass".ToCharArray()));

            Assert.AreEqual(sender, message.Header.Sender);
            Assert.AreEqual(recipient, message.Header.Recipient);
        }

        // TODO[cmp]
        //[Test]
        //public void TestPBMac1ProtectedMessage()
        //{
        //    var kp = RsaKeyPair;
        //    var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

        //    var sender = new GeneralName(new X509Name("CN=Sender"));
        //    var recipient = new GeneralName(new X509Name("CN=Recip"));

        //    IMacFactory pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build("secret".toCharArray());

        //    var certRepMessage = CertRepMessage.GetInstance(DerSequence.FromElement(new DerSequence()));

        //    ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
        //        .SetBody(new PkiBody(PkiBody.TYPE_INIT_REP, certRepMessage))
        //        .AddCmpCertificate(cert)
        //        .Build(pbCalculator);

        //    PBEMacCalculatorProvider macProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        //    Assert.True(message.Verify(macProvider, "secret".ToCharArray()));

        //    Assert.AreEqual(sender, message.Header.Sender);
        //    Assert.AreEqual(recipient, message.Header.Recipient);
        //}

        [Test]
        public void TestConfirmationMessage()
        {
            var kp = RsaKeyPair;
            var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

            var sender = new GeneralName(new X509Name("CN=Sender"));
            var recipient = new GeneralName(new X509Name("CN=Recip"));

            CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                .AddAcceptedCertificate(cert, BigInteger.One)
                .Build();

            var signatureFactory = new Asn1SignatureFactory("MD5withRSA", kp.Private);

            ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
                .SetBody(new PkiBody(PkiBody.TYPE_CERT_CONFIRM, content.ToAsn1Structure()))
                .AddCmpCertificate(cert)
                .Build(signatureFactory);

            Assert.True(message.Verify(kp.Public), "PkiMessage must verify (MD5withRSA)");

            Assert.AreEqual(sender, message.Header.Sender);
            Assert.AreEqual(recipient, message.Header.Recipient);

            content = new CertificateConfirmationContent(CertConfirmContent.GetInstance(message.Body.Content));

            CertificateStatus[] statusList = content.GetStatusMessages();

            Assert.AreEqual(1, statusList.Length);
            Assert.True(statusList[0].IsVerified(cert));
        }

        [Test]
        public void TestSampleCr()
        {
            var pkiMessage = LoadPkiMessage("sample_cr.der");
            var protectedPkiMessage = new ProtectedPkiMessage(new GeneralPkiMessage(pkiMessage));

            Assert.True(protectedPkiMessage.Verify(new PKMacBuilder(), "TopSecret1234".ToCharArray()));
        }

        [Test]
        public void TestSubsequentMessage()
        {
            var kp = RsaKeyPair;
            var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

            var user = new GeneralName(new X509Name("CN=Test"));

            var certificateRequestMessage = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetPublicKey(kp.Public)
                .SetProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert)
                .Build();

            var signatureFactory = new Asn1SignatureFactory("SHA256withRSA", kp.Private);

            var certReqMessages = new CertReqMessages(certificateRequestMessage.ToAsn1Structure());

            ProtectedPkiMessage certRequestMsg = new ProtectedPkiMessageBuilder(user, user)
                .SetTransactionId(new byte[]{ 1, 2, 3, 4, 5 })
                .SetBody(new PkiBody(PkiBody.TYPE_KEY_RECOVERY_REQ, certReqMessages))
                .AddCmpCertificate(cert)
                .Build(signatureFactory);

            byte[] encoded = certRequestMsg.ToAsn1Message().GetDerEncoded();

            ProtectedPkiMessage msg = new ProtectedPkiMessage(new GeneralPkiMessage(encoded));
            certReqMessages = CertReqMessages.GetInstance(msg.Body.Content);
            CertReqMsg certReqMsg = certReqMessages.ToCertReqMsgArray()[0];

            Assert.AreEqual(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, certReqMsg.Pop.Type);
        }

        [Test]
        public void TestServerSideKey()
        {
            // TODO[cmp] The original bc-java version used the EncrypedKey.encryptedValue CHOICE option

            var kp = RsaKeyPair;
            var cert = MakeV3Certificate(kp, "CN=Test", kp, "CN=Test");

            var sender = new GeneralName(new X509Name("CN=Sender"));
            var recipient = new GeneralName(new X509Name("CN=Recip"));

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);

            EncryptedKey privateKey;
            {
                var keyContent = new CmsProcessableByteArray(privateKeyInfo.GetEncoded(Asn1Encodable.Der));

                var contentEncryptor = new CmsContentEncryptorBuilder(NistObjectIdentifiers.IdAes128Cbc).Build();

                var envGen = new CmsEnvelopedDataGenerator();
                envGen.AddKeyTransRecipient(cert);

                var envData = envGen.Generate(keyContent, contentEncryptor);

                privateKey = new EncryptedKey(envData.EnvelopedData);
            }

            var certOrEncCert = new CertOrEncCert(CmpCertificate.GetInstance(cert.GetEncoded()));
            var certifiedKeyPair = new CertifiedKeyPair(certOrEncCert, privateKey, publicationInfo: null);
            var certResponse = new CertResponse(DerInteger.Two, new PkiStatusInfo((int)PkiStatus.Granted),
                certifiedKeyPair, rspInfo: null);

            var certRepMessage = new CertRepMessage(caPubs: null, response: new CertResponse[]{ certResponse });

            var signatureFactory = new Asn1SignatureFactory("MD5withRSA", kp.Private);

            ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
                .SetBody(new PkiBody(PkiBody.TYPE_INIT_REP, certRepMessage))
                .AddCmpCertificate(cert)
                .Build(signatureFactory);

            Assert.True(message.Verify(kp.Public));

            Assert.AreEqual(sender, message.Header.Sender);
            Assert.AreEqual(recipient, message.Header.Recipient);

            CertRepMessage content = CertRepMessage.GetInstance(message.Body.Content);

            CertResponse[] responseList = content.GetResponse();
            Assert.AreEqual(1, responseList.Length);

            CertResponse response = responseList[0];
            Assert.True(response.Status.StatusObject.HasValue((int)PkiStatus.Granted));

            CertifiedKeyPair certKp = response.CertifiedKeyPair;

            // steps to unwrap private key
            EncryptedKey encKey = certKp.PrivateKey;
            Assert.False(encKey.IsEncryptedValue);

            {
                var envData = EnvelopedData.GetInstance(encKey.Value);
                var contentInfo = new Asn1.Cms.ContentInfo(PkcsObjectIdentifiers.EnvelopedData, envData);
                var cmsEnvelopedData = new CmsEnvelopedData(contentInfo);

                RecipientInformationStore recipients = cmsEnvelopedData.GetRecipientInfos();
                foreach (RecipientInformation recipientInfo in cmsEnvelopedData.GetRecipientInfos())
                {
                    Assert.True(recipientInfo.RecipientID.Match(cert));

                    var keyEncAlgOid = recipientInfo.KeyEncryptionAlgorithmID.Algorithm;
                    Assert.AreEqual(PkcsObjectIdentifiers.RsaEncryption, keyEncAlgOid);

                    byte[] recData = recipientInfo.GetContent(kp.Private);
                    Assert.AreEqual(privateKeyInfo, PrivateKeyInfo.GetInstance(recData));
                }
            }
        }

        [Test]
        public void TestNotBeforeNotAfter()
        {
            var rsaKeyPair = RsaKeyPair;

            ImplNotBeforeNotAfterTest(rsaKeyPair, SimpleTest.MakeUtcDateTime(1, 1, 1, 0, 0, 1),
                SimpleTest.MakeUtcDateTime(1, 1, 1, 0, 0, 10));
            ImplNotBeforeNotAfterTest(rsaKeyPair, null, SimpleTest.MakeUtcDateTime(1, 1, 1, 0, 0, 10));
            ImplNotBeforeNotAfterTest(rsaKeyPair, SimpleTest.MakeUtcDateTime(1, 1, 1, 0, 0, 1), null);
        }

        [Test]
        public void TestVerifyBCJavaGeneratedMessage()
        {
            // Test with content generated by bc-java.

            byte[] ind = Hex.Decode(
                "308201ac306e020102a4133011310f300d06035504030c0653656e646572a4" +
                "123010310e300c06035504030c055265636970a140303e06092a864886f67d" +
                "07420d30310414fdccb4ffd7848e6a697bee36cbe0f3722ed7fe2f30070605" +
                "2b0e03021a020203e8300c06082b060105050801020500a10430023000a017" +
                "031500c131c357441daa78eb538bfd9c24870e220fdafaa182011930820115" +
                "308201113081bca003020102020601684a515d5b300d06092a864886f70d01" +
                "01050500300f310d300b06035504030c0454657374301e170d313930313134" +
                "3033303433325a170d3139303432343033303433325a300f310d300b060355" +
                "04030c0454657374305c300d06092a864886f70d0101010500034b00304802" +
                "4100ac1e59ba5f96ba86c86e6d8bbfd43ece04265fa29e6ebdb320388b58af" +
                "365d05b26970cbd26e5b0fa7df2074b90b42a1d16ab270cdb851b53e464b87" +
                "f68377450203010001300d06092a864886f70d0101050500034100264b5b76" +
                "f268e2a992f05ad83783b091ce806a6726912c6200d06b33375ae58fe3c474" +
                "c3a42ad6e572a2c48ae3bf914a7510bb995c3474829cfe71ab679a3db0");

            ProtectedPkiMessage pkiMsg = new ProtectedPkiMessage(PkiMessage.GetInstance(ind));

            PbmParameter pbmParameters = PbmParameter.GetInstance(pkiMsg.Header.ProtectionAlg.Parameters);

            Assert.True(pkiMsg.Verify(new PKMacBuilder().SetParameters(pbmParameters), "secret".ToCharArray()));
        }

        private void ImplNotBeforeNotAfterTest(AsymmetricCipherKeyPair kp, DateTime? notBefore, DateTime? notAfter)
        {
            CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetPublicKey(kp.Public)
                .SetProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

            builder.SetValidity(notBefore, notAfter);
            CertificateRequestMessage msg = builder.Build();

            if (notBefore != null)
            {
                Assert.AreEqual(notBefore.Value, msg.GetCertTemplate().Validity.NotBefore.ToDateTime(),
                    "NotBefore did not match");
            }
            else
            {
                Assert.Null(msg.GetCertTemplate().Validity.NotBefore);
            }

            if (notAfter != null)
            {
                Assert.AreEqual(notAfter.Value, msg.GetCertTemplate().Validity.NotAfter.ToDateTime(),
                    "NotAfter did not match");
            }
            else
            {
                Assert.Null(msg.GetCertTemplate().Validity.NotAfter);
            }
        }

        private static AsymmetricCipherKeyPair CreateRsaKeyPair()
        {
            var kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 512, 100));
            return kpg.GenerateKeyPair();
        }

        private static PkiMessage LoadPkiMessage(string name)
        {
            using (var stream = SimpleTest.FindTestResource("cmp", name))
            {
                return PkiMessage.GetInstance(Streams.ReadAll(stream));
            }
        }

        private static X509Certificate MakeV3Certificate(AsymmetricCipherKeyPair subjectKP, string subjectDN,
            AsymmetricCipherKeyPair issuerKP, string issuerDN)
        {
            TestCertBuilder builder = new TestCertBuilder()
            {
                Issuer = new X509Name(issuerDN),
                Subject = new X509Name(subjectDN),
                NotBefore = DateTime.UtcNow.AddHours(-1),
                NotAfter = DateTime.UtcNow.AddDays(1),
                PublicKey = subjectKP.Public,
                SignatureAlgorithm = "SHA1withRSA",
            };
            //builder.AddAttribute(X509Name.C, "Foo");
            var cert = builder.Build(issuerKP.Private);

            Assert.True(cert.IsSignatureValid(issuerKP.Public));
            return cert;
        }
    }

    public class TestCertBuilder
    {
        private readonly Dictionary<DerObjectIdentifier, string> attrs = new Dictionary<DerObjectIdentifier, string>();
        private readonly List<DerObjectIdentifier> ord = new List<DerObjectIdentifier>();
        private readonly List<string> values = new List<string>();

        private static int serialNumber = 0;

        private static int NextSerialNumber() => Interlocked.Increment(ref serialNumber);

        private static BigInteger AllocateSerialNumber() => BigInteger.ValueOf(NextSerialNumber());

        public DateTime NotBefore { get; set; }

        public DateTime NotAfter { get; set; }

        public AsymmetricKeyParameter PublicKey { get; set; }

        public string SignatureAlgorithm { get; set; }

        public X509Name Issuer { get; set; }

        public X509Name Subject { get; set; }

        public TestCertBuilder AddAttribute(DerObjectIdentifier name, string value)
        {
            attrs[name] = value;
            ord.Add(name);
            values.Add(value);
            return this;
        }

        public X509Certificate Build(AsymmetricKeyParameter privateKey)
        {
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(AllocateSerialNumber());

            if (Issuer != null)
            {
                certGen.SetIssuerDN(Issuer);
            }
            else
            {
                certGen.SetIssuerDN(new X509Name(ord, attrs));
            }

            certGen.SetNotBefore(NotBefore);
            certGen.SetNotAfter(NotAfter);

            if (Subject != null)
            {
                certGen.SetSubjectDN(Subject);
            }
            else
            {
                certGen.SetSubjectDN(new X509Name(ord, attrs));
            }

            certGen.SetPublicKey(PublicKey);

            return certGen.Generate(new Asn1SignatureFactory(SignatureAlgorithm, privateKey, null));
        }
    }
}
