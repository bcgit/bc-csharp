using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cmp.Tests;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf.Tests
{
    [TestFixture]
    public class CrmfTest : SimpleTest
    {
        public override string Name
        {
            get { return "CRMF"; }
        }

        public override void PerformTest()
        {
            TestFromJVM();
            TestBasicMessage();
            TestBasicMessageWithArchiveControl();
            TestBasicMessageWithArchiveControlJVMGenerated();
        }
        
        [Test]
        public void TestFromJVM()
        {
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(Hex.Decode(
                "305c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001"));
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(Hex.Decode("30820153020100300d06092a864886f70d01010105000482013d30820139020100024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b41020301000102400093b384b9021c4cd59888e956cb1e653e736833235315b0e938116da19a9276b1ea1fe33da580a497313f08eb3e7c14627508a4284be04ea3e6ba8cb4b0a5c9022100e2fe0d9f35bfd7ecf196227e5e915a2464478ea7033c6dff4ce6a02961759a49022100d3b093770745dfea42c5c5c31f1a6b797a60dfb5503ae60f70b864452c4a193902203cc761c65b91feb3070cf8377602dd6c191dbfe8a04931fac6108a9a09ea7f61022071bb2a5f06af49cfc8340d3df995ee2c03cdcc22d389f15456511abdf73f9031022065bc10d43192cb3131c53be18a0d41a060d4e0a3324a47e3eb4bf720e1b46b10"));

            byte[] rawMsg = Hex.Decode("3081cc30760201013071a511300f310d300b0603550403130454657374a65c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001a152300d06092a864886f70d01010505000341003120cdb58edfef4a2e1a4bfe96b972007c1d1c949221d266efe28b45ba036b9d534f5dca261dce8f21e134d97e55c3bd76d1460781fd9703f8f9907d1f036c20");

            CertificateRequestMessage msg = new CertificateRequestMessage(rawMsg);
            IsTrue("Pop Valid", msg.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(pubKey)));

            //
            // Vandalize message to check for failure.
            //

            rawMsg[7] ^= 1;
            msg = new CertificateRequestMessage(rawMsg);

            IsTrue("Pop Verified Vandalized Message!", !msg.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(pubKey)));
        }

        [Test]
        public void TestBasicMessage()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            CertificateRequestMessageBuilder certReqBuild = new CertificateRequestMessageBuilder(BigInteger.One);

            certReqBuild.SetSubject(new X509Name("CN=Test"))
                .SetPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public))                
                .SetProofOfPossessionSignKeySigner(new Asn1SignatureFactory("SHA1WithRSA", rsaKeyPair.Private));

            CertificateRequestMessage certificateRequestMessage = certReqBuild.Build();

            IsTrue("Signing Key Pop Valid",certificateRequestMessage.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(rsaKeyPair.Public)));
            IsTrue(certificateRequestMessage.GetCertTemplate().Subject.Equivalent(new X509Name("CN=Test")));
            IsTrue(certificateRequestMessage.GetCertTemplate().PublicKey.Equals(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public)));
        }

        [Test]
        public void TestBasicMessageWithArchiveControl()
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 100));
            AsymmetricCipherKeyPair rsaKeyPair = rsaKeyPairGenerator.GenerateKeyPair();

            TestCertBuilder tcb = new TestCertBuilder();
            tcb.PublicKey = rsaKeyPair.Public;
            tcb.Subject = new X509Name("CN=Test");
            tcb.Issuer = new X509Name("CN=Test");
            tcb.NotBefore = DateTime.UtcNow.AddDays(-1);
            tcb.NotAfter = DateTime.UtcNow.AddDays(1);
            tcb.SignatureAlgorithm = "Sha1WithRSAEncryption";

            X509Certificate cert = tcb.Build(rsaKeyPair.Private);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);
            PrivateKeyInfo privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaKeyPair.Private);

            CertificateRequestMessageBuilder certificateRequestMessageBuilder = new CertificateRequestMessageBuilder(BigInteger.One);
            certificateRequestMessageBuilder.SetSubject(new X509Name("CN=Test"));
            certificateRequestMessageBuilder.SetPublicKey(publicKeyInfo);
           
            certificateRequestMessageBuilder.AddControl(
                new PkiArchiveControlBuilder(privateInfo, new GeneralName(new X509Name("CN=Test")))
                    .AddRecipientGenerator(new KeyTransRecipientInfoGenerator(cert, new Asn1KeyWrapper("RSA/None/OAEPwithSHA256andMGF1Padding", cert)))
                    .Build(new CmsContentEncryptorBuilder(NistObjectIdentifiers.IdAes128Cbc).Build())
            );

            CertificateRequestMessage msg = certificateRequestMessageBuilder.Build();

            IsTrue(Arrays.AreEqual(msg.GetCertTemplate().Subject.GetEncoded(), new X509Name("CN=Test").GetEncoded()));
            IsTrue(Arrays.AreEqual(msg.GetCertTemplate().PublicKey.GetEncoded(),publicKeyInfo.GetEncoded()));

            CheckCertReqMsgWithArchiveControl(rsaKeyPair,msg);
            CheckCertReqMsgWithArchiveControl(rsaKeyPair, new CertificateRequestMessage(msg.GetEncoded()));
        }

        [Test]
        public void TestBasicMessageWithArchiveControlJVMGenerated()
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(
                Hex.Decode("305c300d06092a864886f70d0101010500034b003048024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b3070203010001"));
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(
                Hex.Decode("30820154020100300d06092a864886f70d01010105000482013e3082013a020100024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b307020301000102400831deacfe21a9331902d7f648e1297c563196b00c70971fb439098cb5c1618925bdbac4c66b30f8956660220f326f51e5a1725ce690165154fb62fa14497265022100e54943be1b4951e127f6e79c5ab333cba4b0fff0b5e59328d6393ba98dc0e6c3022100bd6da58ce195146a1d3825ec2a622cf4962da653096bea87fbd9a94db266a66d0221008948bcceeef78f97089ec53ed0efcb6b7b489f7638f32491a6f2cdce4f99d89102204eb1b066d8883054ed12985e863506ec0d3fa5ab356cc99ff876b228ff0639f9022024049aaf39bf9a0ddfbd4caee277d0a9f07d075faae12571176a5c0ca40415c0"));

            CertificateRequestMessage msg = new CertificateRequestMessage(
                Hex.Decode("308202af308202ab0201013071a511300f310d300b0603550403130454657374a65c300d06092a864886f70d0101010500034b003048024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b3070203010001308202313082022d06092b0601050507050104a082021ea082021a0201003171306f0201003019300f310d300b06035504030c04546573740206016859de5806300d06092a864886f70d0101010500044066f1a72f808908af784b83c07895276104d7c4caaee6090212ce5b27517aec510425b784352b5342c999f844b8796286f10a59807e290f06aa39f8cba86dd6bf308201a0060b2a864886f70d0109100115301d060960864801650304010204104aceaa277cc7974ea2a775ff9db6062580820170c648e70c25c4789d2ff4ed398e5536efb45d2dd8ba76a628ad30bf9596a18337afc0f596f0c18e05fb3fa9944ed9691dae1d9b327b5bbafaaa63efb0e22d675811c27bfb023b80184325fd4b67b3b9e41bf43c5583a86433b230e09a34b61397ddff0eadf10c883fc1f01860e2a56ab4002dcc4d4925c53e09dde0b99928fdf602bce544722155cebd8816e91a411a99feea07695774cd8883034022d57f64e9cd3383c3125c48db2936b7395a22b17910be1f2c0b8650bdb5bd752ffc40fcd30169e5ae3a4ac7ad9cc850e9c17bbcf8e1a1898d0d8be19145c484467b8f1124657a5e08c10fc67416274990cc16d55c9fb76c265dd436b7e803425892297f1a08e4fab8e178874b2b3bf9c749693d609db208e9a3ebbddd26cd6a1b33c0201532170dc6c303e7ac0c42ba0bc54dfb928b228842b6bb08d8dc411d262dabf140a8b5a5c67ea486c1877a2fc000981d54cf2decaf1cfeebcf83134992b09a2b1fe9e02da25b874604b5d8bbd609875ba8"));

            AsymmetricCipherKeyPair rsaKeyPair = new AsymmetricCipherKeyPair(publicKey,privateKey);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            IsTrue(msg.GetCertTemplate().Subject.Equivalent(new X509Name("CN=Test")));
            IsTrue(Arrays.AreEqual(msg.GetCertTemplate().PublicKey.GetEncoded(), publicKeyInfo.GetEncoded()));

            CheckCertReqMsgWithArchiveControl(rsaKeyPair, msg);
            CheckCertReqMsgWithArchiveControl(rsaKeyPair, new CertificateRequestMessage(msg.GetEncoded()));
        
            CheckCertReqMsgWithArchiveControl(rsaKeyPair,msg);
        }

        private void CheckCertReqMsgWithArchiveControl(AsymmetricCipherKeyPair kp, CertificateRequestMessage certReqMessage)
        {
            PkiArchiveControl archiveControl = (PkiArchiveControl)certReqMessage.GetControl(
                CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions);
            IsEquals("Archive type", PkiArchiveControl.encryptedPrivKey, archiveControl.ArchiveType);

            IsTrue(archiveControl.EnvelopedData);
            RecipientInformationStore recips = archiveControl.GetEnvelopedData().GetRecipientInfos();

            var collection = recips.GetRecipients();

            IsTrue(collection.Count == 1);
            KeyTransRecipientInformation info = (KeyTransRecipientInformation)collection[0];

            EncKeyWithID encKeyWithId = EncKeyWithID.GetInstance(info.GetContent(kp.Private));

            IsTrue(encKeyWithId.HasIdentifier);
            IsTrue(!encKeyWithId.IsIdentifierUtf8String); // GeneralName at this point.
            
            IsTrue("Name", X509Name.GetInstance(GeneralName.GetInstance(encKeyWithId.Identifier).Name).Equivalent(new X509Name("CN=Test")));
          
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            IsTrue("Private Key", Arrays.AreEqual(privateKeyInfo.GetEncoded(), encKeyWithId.PrivateKey.GetEncoded()));
        }
    }
}
