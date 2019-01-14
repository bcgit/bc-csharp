using System;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cmp;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace crypto.test.src.ejbca.test
{
    [TestFixture]
    public class EnrollmentExampleTest
    {

        [Test]      
        public void TestEnrollmentRAWithSharedSecret()
        {
            long certReqId = 1;
            SecureRandom secureRandom = new SecureRandom();

            byte[] senderNonce = new byte[20];
            secureRandom.NextBytes(senderNonce);

            byte[] transactionId = Strings.ToAsciiByteArray("MyTransactionId");


            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();


            CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(BigInteger.ValueOf(certReqId));
            X509NameEntryConverter dnconverter = new X509DefaultEntryConverter();
           
            X509Name issuerDN = X509Name.GetInstance(new X509Name("CN=AdminCA1").ToAsn1Object());
            X509Name subjectDN = X509Name.GetInstance(new X509Name("CN=user", dnconverter).ToAsn1Object());
            msgbuilder.SetIssuer(issuerDN);
            msgbuilder.SetSubject(subjectDN);
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            msgbuilder.SetPublicKey(keyInfo);
            GeneralName sender = new GeneralName(subjectDN);
            msgbuilder.SetAuthInfoSender(sender);
            // RAVerified POP
            msgbuilder.SetProofOfPossessionRaVerified();
            CertificateRequestMessage msg = msgbuilder.Build();
            GeneralName recipient = new GeneralName(issuerDN);

            ProtectedPkiMessageBuilder pbuilder = new ProtectedPkiMessageBuilder(sender, recipient);
            pbuilder.SetMessageTime(new DerGeneralizedTime(DateTime.Now));
            // senderNonce
            pbuilder.SetSenderNonce(senderNonce);
            // TransactionId
            pbuilder.SetTransactionId(transactionId);
            // Key Id used (required) by the recipient to do a lot of stuff
            pbuilder.SetSenderKID(Strings.ToAsciiByteArray("KeyId"));

            
            CertReqMessages msgs = new CertReqMessages(msg.ToAsn1Structure());
            PkiBody pkibody = new PkiBody(PkiBody.TYPE_INIT_REQ, msgs);
            pbuilder.SetBody(pkibody);

                                 
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier("1.3.14.3.2.26"); // SHA1
            AlgorithmIdentifier macAlg = new AlgorithmIdentifier("1.2.840.113549.2.7"); // HMAC/SHA1

            PkMacFactory macFactory = new PkMacFactory(digAlg,macAlg);
            macFactory.Password = Strings.ToAsciiByteArray("password");

            ProtectedPkiMessage message = pbuilder.Build(macFactory);
                                  

        }

    }
}