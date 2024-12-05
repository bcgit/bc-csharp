using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp.Tests
{
    [TestFixture]
    public class PqcTest
    {
        private SecureRandom m_random = null;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_random = new SecureRandom();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            m_random = null;
        }

        [Test]
        public void MLKemRequestWithMLDsaCA()
        {
            char[] senderMacPassword = "secret".ToCharArray();
            GeneralName sender = new GeneralName(new X509Name("CN=ML-KEM Subject"));
            GeneralName recipient = new GeneralName(new X509Name("CN=ML-DSA Issuer"));

            var mlDsaKpg = GeneratorUtilities.GetKeyPairGenerator("ML-DSA");
            mlDsaKpg.Init(new MLDsaKeyGenerationParameters(m_random, NistObjectIdentifiers.id_ml_dsa_65));

            var mlDsaKP = mlDsaKpg.GenerateKeyPair();

            X509Certificate caCert = MakeV3Certificate("ML-DSA-65", "CN=ML-DSA Issuer", mlDsaKP);

            var mlKemKpg = GeneratorUtilities.GetKeyPairGenerator("ML-KEM");
            mlKemKpg.Init(new MLKemKeyGenerationParameters(m_random, NistObjectIdentifiers.id_alg_ml_kem_768));

            var mlKemKP = mlKemKpg.GenerateKeyPair();

            // initial request

            CertificateRequestMessageBuilder certReqBuild = new CertificateRequestMessageBuilder(
                certReqId: BigInteger.One);
            certReqBuild
                .SetPublicKey(mlKemKP.Public)
                .SetSubject(X509Name.GetInstance(sender.Name))
                .SetProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

            CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();
            certReqMsgsBldr.AddRequest(certReqBuild.Build());

            // TODO Try to replicate the bc-java MAC calculation
            //MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

            //var macAlgID = DefaultMacAlgorithmFinder.Instance.Find("HmacSHA256");
            var senderMacBuilder = new PKMacBuilder();
            var senderMacFactory = senderMacBuilder.Build(senderMacPassword);

            ProtectedPkiMessage message = new ProtectedPkiMessageBuilder(sender, recipient)
                .SetBody(PkiBody.TYPE_INIT_REQ, certReqMsgsBldr.Build())
                .Build(senderMacFactory);

            // extract

            Assert.True(message.ProtectionAlgorithm.Equals(senderMacFactory.AlgorithmDetails));

            // TODO Try to replicate the bc-java MAC verification
            //PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();
            //assertTrue(message.verify(macCalcProvider, senderMacPassword));
            Assert.True(message.Verify(senderMacBuilder, senderMacPassword));

            Assert.AreEqual(PkiBody.TYPE_INIT_REQ, message.Body.Type);

            CertificateReqMessages requestMessages = CertificateReqMessages.FromPkiBody(message.Body);
            CertificateRequestMessage senderReqMessage = requestMessages.GetRequests()[0];
            CertTemplate certTemplate = senderReqMessage.GetCertTemplate();

            X509Certificate cert = MakeV3Certificate("ML-DSA-65", certTemplate.PublicKey, certTemplate.Subject, mlDsaKP,
                "CN=ML-DSA Issuer");

            // Send response with encrypted certificate
            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

            // TODO[cmp]: Need KemRecipientInfo support from CMS
            //edGen.AddRecipientInfoGenerator(
            //    new JceKEMRecipientInfoGenerator(
            //        senderReqMessage.getCertReqId().getEncoded(),
            //        new JcaX509CertificateConverter()
            //            .setProvider("BC")
            //            .getCertificate(cert)
            //            .getPublicKey(),
            //        CMSAlgorithm.AES256_WRAP)
            //        .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

            //        CMSEnvelopedData encryptedCert = edGen.generate(
            //            new CMSProcessableCMPCertificate(cert),
            //            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

            //CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.GetCertReqID(),
            //    new PkiStatusInfo(PkiStatusEncodable.granted));

            //certRespBuilder.WithCertificate(encryptedCert);

            //CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

            //repMessageBuilder.AddCertificateResponse(certRespBuilder.Build());

            //var signer = new Asn1SignatureFactory("ML-DSA-65", mlDsaKP.Private);

            //CertificateRepMessage repMessage = repMessageBuilder.Build();

            //ProtectedPkiMessage responsePkixMessage = new ProtectedPkiMessageBuilder(sender, recipient)
            //    .SetBody(PkiBody.TYPE_INIT_REP, repMessage)
            //    .Build(signer);

            //// decrypt the certificate

            //Assert.True(responsePkixMessage.Verify(caCert.GetPublicKey()));

            //CertificateRepMessage certRepMessage = CertificateRepMessage.FromPkiBody(responsePkixMessage.Body);

            //CertificateResponse certResp = certRepMessage.GetResponses()[0];

            //Assert.True(certResp.HasEncryptedCertificate);

            //// this is the long-way to decrypt, for testing
            //CMSEnvelopedData receivedEnvelope = new CMSEnvelopedData(certResp.getEncryptedCertificate().toASN1Structure().getEncoded(ASN1Encoding.DL));

            //JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert_enveloped.pem"));
            //pOut.writeObject(receivedEnvelope.toASN1Structure());
            //pOut.close();

            //pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_priv.pem"));
            //pOut.writeObject(kybKp.getPrivate());
            //pOut.close();

            //pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert.pem"));
            //pOut.writeObject(cert);
            //pOut.close();

            //pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert.pem"));
            //pOut.writeObject(caCert);
            //pOut.close();

            //RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
            //Collection c = recipients.getRecipients();

            //assertEquals(1, c.size());

            //RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

            //assertEquals(recInfo.getKeyEncryptionAlgOID(), NISTObjectIdentifiers.id_alg_ml_kem_768.getId());

            //byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(kybKp.getPrivate()).setProvider("BC"));

            //assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

            //// this is the preferred way of recovering an encrypted certificate

            //CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(kybKp.getPrivate()));

            //X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

            //X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

            //assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

            //// confirmation message calculation

            //CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            //    .addAcceptedCertificate(cert, BigInteger.ONE)
            //    .build(new JcaDigestCalculatorProviderBuilder().build());

            //message = new ProtectedPKIMessageBuilder(sender, recipient)
            //    .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            //    .build(senderMacCalculator);

            //assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
            //assertEquals(PKIBody.TYPE_CERT_CONFIRM, message.getBody().getType());

            //// confirmation receiving

            //CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(message.getBody());

            //assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        }

        private static X509Certificate MakeV3Certificate(string sigAlgName, string _subDN, AsymmetricCipherKeyPair issKP)
        {
            AsymmetricKeyParameter issPriv = issKP.Private;
            AsymmetricKeyParameter issPub = issKP.Public;

            var subject = new X509Name(_subDN);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(subject);
            certGen.SetSerialNumber(BigInteger.ValueOf(DateTimeUtilities.CurrentUnixMs()));
            certGen.SetNotBefore(DateTime.UtcNow);
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
            certGen.SetSubjectDN(subject);
            certGen.SetPublicKey(issPub);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(0));

            var signer = new Asn1SignatureFactory(sigAlgName, issPriv);

            X509Certificate cert = certGen.Generate(signer);

            Assert.True(cert.IsSignatureValid(issPub));

            return cert;
        }

        private static X509Certificate MakeV3Certificate(string sigAlgName, SubjectPublicKeyInfo pubKey, X509Name _subDN,
            AsymmetricCipherKeyPair issKP, string _issDN)
        {
            AsymmetricKeyParameter issPriv = issKP.Private;
            AsymmetricKeyParameter issPub = issKP.Public;

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(new X509Name(_issDN));
            certGen.SetSerialNumber(BigInteger.ValueOf(DateTimeUtilities.CurrentUnixMs()));
            certGen.SetNotBefore(DateTime.UtcNow);
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
            certGen.SetSubjectDN(_subDN);
            certGen.SetSubjectPublicKeyInfo(pubKey);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));

            var signer = new Asn1SignatureFactory(sigAlgName, issPriv);

            X509Certificate cert = certGen.Generate(signer);

            Assert.True(cert.IsSignatureValid(issPub));

            return cert;
        }
    }
}
