using System;
using System.Collections;

using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp.Tests
{
    [TestFixture]
    public class ProtectedMessageTest : SimpleTest
    {
        public override string Name
        {
            get { return "ProtectedMessageTest"; }
        }

        public override void PerformTest()
        {
            TestVerifyBCJavaGeneratedMessage();
            TestSubsequentMessage();
            TestMacProtectedMessage();
            TestProtectedMessage();
            TestConfirmationMessage();
            TestSampleCr();        
        }

//        [Test]
//        public void TestServerSideKey()
//        {
//            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
//            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
//            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();
//
//            TestCertBuilder builder = new TestCertBuilder()
//            {
//                Issuer = new X509Name("CN=Test"),
//                Subject =  new X509Name("CN=Test"),
//                NotBefore = DateTime.UtcNow.AddDays(-1),
//                NotAfter = DateTime.UtcNow.AddDays(1),
//                PublicKey = rsaKeyPair.Public,
//                SignatureAlgorithm = "MD5WithRSAEncryption"
//            };
//
//            builder.AddAttribute(X509Name.C, "Foo");
//            X509Certificate cert = builder.Build(rsaKeyPair.Private);
//               
//            GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
//            GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));
//
//            
//
//        }

        [Test]
        public void TestNotBeforeNotAfter()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            doNotBeforeNotAfterTest(rsaKeyPair, new DateTime(1,1,1,0,0,1), new DateTime(1,1,1,0,0,10)); 
            doNotBeforeNotAfterTest(rsaKeyPair, DateTime.MinValue, new DateTime(1, 1, 1, 0, 0, 10));
            doNotBeforeNotAfterTest(rsaKeyPair, new DateTime(1, 1, 1, 0, 0, 1), DateTime.MinValue);
        }


        private void doNotBeforeNotAfterTest(AsymmetricCipherKeyPair kp, DateTime notBefore, DateTime notAfter)
        {
            CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public))
                .SetProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

            builder.SetValidity(new Time(notBefore), new Time(notAfter));
            CertificateRequestMessage msg = builder.Build();

            if (!notBefore.Equals(DateTime.MinValue))
            {
                IsTrue("NotBefore did not match",(notBefore.Equals(msg.GetCertTemplate().Validity.NotBefore.ToDateTime())));
            }
            else
            {
                IsTrue("Expected NotBefore to empty.",DateTime.MinValue == msg.GetCertTemplate().Validity.NotBefore.ToDateTime());
            }

            if (!notAfter.Equals(DateTime.MinValue))
            {
                IsTrue("NotAfter did not match", (notAfter.Equals(msg.GetCertTemplate().Validity.NotAfter.ToDateTime())));
            }
            else
            {
                IsTrue("Expected NotAfter to be empty.", DateTime.MinValue == msg.GetCertTemplate().Validity.NotAfter.ToDateTime());
            }

        }


        [Test]
        public void TestSubsequentMessage()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            TestCertBuilder builder = new TestCertBuilder()
            {
                NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter = DateTime.UtcNow.AddDays(1),
                PublicKey = rsaKeyPair.Public,
                SignatureAlgorithm = "Sha1WithRSAEncryption"

            };

            X509Certificate cert = builder.Build(rsaKeyPair.Private);

            GeneralName user = new GeneralName(new X509Name("CN=Test"));

            CertificateRequestMessageBuilder crmBuiler = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public))
                .SetProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

            ISignatureFactory sigFact = new Asn1SignatureFactory("SHA256WithRSA", rsaKeyPair.Private);

            ProtectedPkiMessage certRequestMsg = new ProtectedPkiMessageBuilder(user,user)
                .SetTransactionId(new byte[]{1,2,3,4,5})
                .SetBody(new PkiBody(PkiBody.TYPE_KEY_RECOVERY_REQ, new CertReqMessages(new CertReqMsg[]{crmBuiler.Build().ToAsn1Structure()})))
                .AddCmpCertificate(cert)            
                .Build(sigFact);

            ProtectedPkiMessage msg = new ProtectedPkiMessage(new GeneralPKIMessage(certRequestMsg.ToAsn1Message().GetDerEncoded()));
            CertReqMessages reqMsgs = CertReqMessages.GetInstance(msg.Body.Content);
            CertReqMsg reqMsg = reqMsgs.ToCertReqMsgArray()[0];
            IsEquals(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, reqMsg.Popo.Type);

        }



        [Test]
        public void TestSampleCr()
        {
            byte[] raw = Base64.Decode(
                "MIIB5TCB3AIBAqQdMBsxDDAKBgNVBAMMA0FSUDELMAkGA1UEBhMCQ0ikOTA3MREwDwYDVQQDDAhBZG1pbkNBM" +
                "TEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRaFGMEQGCSqGSIb2fQdCDTA3BBxzYWx0Tm9NYX" +
                "R0ZXJXaGF0VGhpc1N0cmluZ0lzMAcGBSsOAwIaAgIEADAKBggrBgEFBQgBAqIQBA5TZW5kZXJLSUQtMjAwOKQ" +
                "PBA0xMjAzNjA3MDE1OTQ0pRIEEOPfE1DMncRUdrBj8KelgsCigeowgecwgeQwgd0CAQAwgcGlHTAbMQwwCgYD" +
                "VQQDDANBUlAxCzAJBgNVBAYTAkNIpoGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrrv4e42olM2YJqSbCN" +
                "d19EtW7d6T8HYvcSU5wsm5icKFkxyD5jrO/2xYh3zqUFYwZap0pA7qbhxk5sEne2ywVpt2lGSmpAU8M7hC9oh" +
                "Ep9wvv+3+td5MEO+qMuWWxF8OZBlYIFBZ/k+pGlU+4XlBP5Ai6pu/EI/0A+1/bcGs0sQIDAQABMBQwEgYJKwY" +
                "BBQUHBQEBDAVEVU1NWaACBQCgFwMVAO73HUPF//mY5+E714Cv5oprt0kO\r\n");

            ProtectedPkiMessage msg = new ProtectedPkiMessage(new GeneralPKIMessage(raw));

            
                       
            IsTrue(msg.Verify(new PKMacBuilder(), "TopSecret1234".ToCharArray()));

        }


        [Test]
        public void TestConfirmationMessage()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            TestCertBuilder builder = new TestCertBuilder()
            {
                NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter = DateTime.UtcNow.AddDays(1),
                PublicKey = rsaKeyPair.Public,
                SignatureAlgorithm = "Sha1WithRSAEncryption"

            };

            builder.AddAttribute(X509Name.C, "Foo");
            X509Certificate cert = builder.Build(rsaKeyPair.Private);

            GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
            GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));

            CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                .AddAcceptedCertificate(cert, BigInteger.One)
                .Build();

            ProtectedPkiMessageBuilder msgBuilder = new ProtectedPkiMessageBuilder(sender, recipient);
            msgBuilder.SetBody(new PkiBody(PkiBody.TYPE_CERT_CONFIRM, content.ToAsn1Structure()));            
            msgBuilder.AddCmpCertificate(cert);

            ISignatureFactory sigFact = new Asn1SignatureFactory("MD5WithRSA", rsaKeyPair.Private);
            ProtectedPkiMessage msg = msgBuilder.Build(sigFact);

            IVerifierFactory verifierFactory = new Asn1VerifierFactory("MD5WithRSA", rsaKeyPair.Public);

            IsTrue("PKIMessage must verify (MD5withRSA)", msg.Verify(verifierFactory));

            IsEquals(sender,msg.Header.Sender);
            IsEquals(recipient,msg.Header.Recipient);

            content = new CertificateConfirmationContent(CertConfirmContent.GetInstance(msg.Body.Content), new DefaultDigestAlgorithmIdentifierFinder());
            CertificateStatus[] statusList = content.GetStatusMessages();
            IsEquals(1,statusList.Length);
            IsTrue(statusList[0].IsVerified(cert));
        }



        [Test]
        public  void TestProtectedMessage()
        {
           RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537),new SecureRandom(),2048,100));
           AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            TestCertBuilder builder = new TestCertBuilder()
            {
                NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter =  DateTime.UtcNow.AddDays(1),
                PublicKey = rsaKeyPair.Public,
                SignatureAlgorithm = "Sha1WithRSAEncryption"
                      
            };

            builder.AddAttribute(X509Name.C, "Foo");
            X509Certificate cert = builder.Build(rsaKeyPair.Private);

            GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
            GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));
          
            ProtectedPkiMessageBuilder msgBuilder = new ProtectedPkiMessageBuilder(sender,recipient);
            msgBuilder.AddCmpCertificate(cert);
           
            ISignatureFactory sigFact = new Asn1SignatureFactory("MD5WithRSA",rsaKeyPair.Private);

            ProtectedPkiMessage msg =  msgBuilder.Build(sigFact);

            X509Certificate certificate = msg.GetCertificates()[0];

            IVerifierFactory verifierFactory = new Asn1VerifierFactory("MD5WithRSA", rsaKeyPair.Public);

            IsTrue("PKIMessage must verify (MD5withRSA)",msg.Verify(verifierFactory));
        }

        [Test]
        public void TestMacProtectedMessage()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048,
                100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            TestCertBuilder builder = new TestCertBuilder()
            {
                NotBefore = DateTime.UtcNow.AddDays(-1),
                NotAfter = DateTime.UtcNow.AddDays(1),
                PublicKey = rsaKeyPair.Public,
                SignatureAlgorithm = "Sha1WithRSAEncryption"

            };

            builder.AddAttribute(X509Name.C, "Foo");
            X509Certificate cert = builder.Build(rsaKeyPair.Private);

            GeneralName sender = new GeneralName(new X509Name("CN=Sender"));
            GeneralName recipient = new GeneralName(new X509Name("CN=Recip"));

            ProtectedPkiMessageBuilder msgBuilder = new ProtectedPkiMessageBuilder(sender, recipient);
            msgBuilder.AddCmpCertificate(cert);

            //
            // Default instance.
            //

            PKMacBuilder macFactory = new PKMacBuilder();
            ProtectedPkiMessage msg = msgBuilder.Build(macFactory.Build("testpass".ToCharArray()));

            IsTrue(msg.Verify(macFactory, "testpass".ToCharArray()));
        }

     
        

        [Test]
        public void TestVerifyBCJavaGeneratedMessage()
        {
        //
        // Test with content generated by BC-JAVA version.
        //

        ICipherParameters publicKey = PublicKeyFactory.CreateKey(Hex.Decode(
            "305c300d06092a864886f70d0101010500034b003048024100ac1e59ba5f96" +
            "ba86c86e6d8bbfd43ece04265fa29e6ebdb320388b58af365d05b26970cbd2" +
            "6e5b0fa7df2074b90b42a1d16ab270cdb851b53e464b87f683774502030100" +
            "01"));
        ICipherParameters privateKey = PrivateKeyFactory.CreateKey(Hex.Decode(
            "30820155020100300d06092a864886f70d01010105000482013f3082013b02" +
            "0100024100ac1e59ba5f96ba86c86e6d8bbfd43ece04265fa29e6ebdb32038" +
            "8b58af365d05b26970cbd26e5b0fa7df2074b90b42a1d16ab270cdb851b53e" +
            "464b87f68377450203010001024046f3f208570c735349bfe00fdaa1fbcc00" +
            "c0f2eebe42279876a168ac43fa74a8cdf9a1bb49066c07cfcfa7196f69f2b9" +
            "419d378109db967891428c50273dcc37022100d488dc3fb86f404d726a8166" +
            "b2a9aba9bee12fdbf38470a62403a2a20bad0977022100cf51874e479b141f" +
            "9915533bf54d68f1940f84d7fe6130538ff01a23e3493423022100986f94f1" +
            "0afa9837341219bfabf32fd16ebb9a94fa630a5ccf45e036b383275f02201b" +
            "6dff07f563684b31f6e757548254733a12bf91d05f4d8490d3c4b1a0ddcb9f" +
            "02210087c3b2049e9a3edfc4cb40a3a275dabf7ffff80b467157e384603042" +
            "3fe91d68"));

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

        IsTrue(pkiMsg.Verify(new PKMacBuilder().SetParameters(pbmParameters), "secret".ToCharArray()));
    }


    
}

    public class TestCertBuilder
    {
        IDictionary attrs = new Hashtable();
        IList ord = new ArrayList();
        IList values = new ArrayList();

        public DateTime NotBefore { get; set; }

        public DateTime NotAfter { get; set; }

        public AsymmetricKeyParameter PublicKey { get; set; }

        public String SignatureAlgorithm { get; set; }

        public X509Name Issuer { get; set; }
        public X509Name Subject { get; set; }

        public TestCertBuilder AddAttribute(DerObjectIdentifier name, Object value)
        {
            attrs[name] = value;
            ord.Add(name);
            values.Add(value);
            return this;
        }

        public X509Certificate Build(AsymmetricKeyParameter privateKey)
        {
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.One);

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
            certGen.SetSignatureAlgorithm(SignatureAlgorithm);

            return certGen.Generate(privateKey);
        }
    }
}
