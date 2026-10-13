using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
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
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf.Tests
{
    [TestFixture]
    public class CrmfTest
    {
        [Test]
        public void MessageFromJVM()
        {
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(Hex.Decode(
                "305c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001"));
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(Hex.Decode("30820153020100300d06092a864886f70d01010105000482013d30820139020100024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b41020301000102400093b384b9021c4cd59888e956cb1e653e736833235315b0e938116da19a9276b1ea1fe33da580a497313f08eb3e7c14627508a4284be04ea3e6ba8cb4b0a5c9022100e2fe0d9f35bfd7ecf196227e5e915a2464478ea7033c6dff4ce6a02961759a49022100d3b093770745dfea42c5c5c31f1a6b797a60dfb5503ae60f70b864452c4a193902203cc761c65b91feb3070cf8377602dd6c191dbfe8a04931fac6108a9a09ea7f61022071bb2a5f06af49cfc8340d3df995ee2c03cdcc22d389f15456511abdf73f9031022065bc10d43192cb3131c53be18a0d41a060d4e0a3324a47e3eb4bf720e1b46b10"));

            byte[] rawMsg = Hex.Decode("3081cc30760201013071a511300f310d300b0603550403130454657374a65c300d06092a864886f70d0101010500034b003048024100bbb3f6a5031fbb1feedbfed7584a4f6321ccdc16b9526b0f6e31859328db35a6ec420a98e14fb3bcf192004b1aa6fc9269410204785cc01317232feb545a7b410203010001a152300d06092a864886f70d01010505000341003120cdb58edfef4a2e1a4bfe96b972007c1d1c949221d266efe28b45ba036b9d534f5dca261dce8f21e134d97e55c3bd76d1460781fd9703f8f9907d1f036c20");

            CertificateRequestMessage msg = new CertificateRequestMessage(rawMsg);
            Assert.That(msg.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(pubKey)), "Pop Valid");

            //
            // Vandalize message to check for failure.
            //

            rawMsg[7] ^= 1;
            msg = new CertificateRequestMessage(rawMsg);

            Assert.That(!msg.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(pubKey)), "Pop Verified Vandalized Message!");
        }

        [Test]
        public void PKMacIterationCountCeiling()
        {
            AlgorithmIdentifier owf = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);
            AlgorithmIdentifier mac = new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance);
            byte[] salt = new byte[20];

            // A PKMACBuilder with no explicit ceiling must still reject an attacker-declared iteration
            // count (from an untrusted CMP PBMParameter) before the iterated hash runs.
            PbmParameter hostile = new PbmParameter(salt, owf, int.MaxValue, mac);
            try
            {
                new PKMacBuilder().SetParameters(hostile);
                Assert.Fail("no exception on oversized iteration count");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith("iteration count exceeds limit"));
            }

            // A legitimate count is still accepted.
            PbmParameter benign = new PbmParameter(salt, owf, 1000, mac);
            new PKMacBuilder().SetParameters(benign);
        }

        [Test]
        public void PKMacIterationCountNegative()
        {
            AlgorithmIdentifier owf = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);
            AlgorithmIdentifier mac = new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance);
            byte[] salt = new byte[20];

            // A negative iteration count must be rejected rather than silently accepted (a single OWF pass) or crashing
            // IntValueExact when out of int range.
            PbmParameter negative = new PbmParameter(new DerOctetString(salt), owf, DerInteger.ValueOf(-1), mac);
            try
            {
                new PKMacBuilder().SetParameters(negative);
                Assert.Fail("no exception on negative iteration count");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith("iteration count less than 1"));
            }
        }

        [Test]
        public void PKMacIterationCountOutsideInt32()
        {
            AlgorithmIdentifier owf = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);
            AlgorithmIdentifier mac = new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance);
            byte[] salt = new byte[20];

            // An attacker-declared iteration count larger than int.MaxValue (encoded directly as a DerInteger in an
            // untrusted CMP PBMParameter) must be rejected with the same typed ArgumentException as an in-range
            // oversized count - not leak an ArithmeticException from IntValueExact past the verifier's throws contract.
            PbmParameter beyondInt = new PbmParameter(new DerOctetString(salt), owf,
                new DerInteger(BigInteger.ValueOf(int.MaxValue).Add(BigInteger.One)), mac);
            try
            {
                new PKMacBuilder().SetParameters(beyondInt);
                Assert.Fail("no exception on out-of-int-range iteration count");
            }
            catch (ArgumentException e)
            {
                Assert.That(e.Message.StartsWith("iteration count outside Int32 range"));
            }
        }

        [Test]
        public void BasicMessage()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            CertificateRequestMessageBuilder crmBuilder = new CertificateRequestMessageBuilder(BigInteger.One);

            crmBuilder.SetSubject(new X509Name("CN=Test"))
                .SetPublicKey(rsaKeyPair.Public)
                .SetProofOfPossessionSignKeySigner(new Asn1SignatureFactory("SHA1WithRSA", rsaKeyPair.Private));

            CertificateRequestMessage crm = crmBuilder.Build();

            Assert.That(crm.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(rsaKeyPair.Public)),
                "Signing Key Pop Valid");

            var certTemplate = crm.GetCertTemplate();
            Assert.That(certTemplate.Subject.Equivalent(new X509Name("CN=Test")));
            Assert.That(certTemplate.PublicKey.Equals(spki));
        }

        [Test]
        public void BasicMessageWithArchiveControl()
        {
            var rsaKeyPair = GenerateRsaKeyPair(1024);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            TestCertBuilder tcb = new TestCertBuilder();
            tcb.PublicKey = rsaKeyPair.Public;
            tcb.Subject = new X509Name("CN=Test");
            tcb.Issuer = new X509Name("CN=Test");
            tcb.NotBefore = DateTime.UtcNow.AddDays(-1);
            tcb.NotAfter = DateTime.UtcNow.AddDays(1);
            tcb.SignatureAlgorithm = "Sha1WithRSAEncryption";

            X509Certificate cert = tcb.Build(rsaKeyPair.Private);

            PrivateKeyInfo privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaKeyPair.Private);

            CertificateRequestMessageBuilder crmBuilder = new CertificateRequestMessageBuilder(BigInteger.One);
            crmBuilder.SetSubject(new X509Name("CN=Test"));
            crmBuilder.SetSubjectPublicKeyInfo(spki);

            crmBuilder.AddControl(
                new PkiArchiveControlBuilder(privateInfo, new GeneralName(new X509Name("CN=Test")))
                    .AddRecipientGenerator(new KeyTransRecipientInfoGenerator(cert,
                        new Asn1KeyWrapper("RSA/None/OAEPwithSHA256andMGF1Padding", cert)))
                    .Build(new CmsContentEncryptorBuilder(NistObjectIdentifiers.IdAes128Cbc).Build())
            );

            CertificateRequestMessage crm = crmBuilder.Build();

            var certTemplate = crm.GetCertTemplate();
            Assert.That(Arrays.AreEqual(certTemplate.Subject.GetEncoded(), new X509Name("CN=Test").GetEncoded()));
            Assert.That(Arrays.AreEqual(certTemplate.PublicKey.GetEncoded(), spki.GetEncoded()));

            CheckCertReqMsgWithArchiveControl(rsaKeyPair, rsaKeyPair.Private, crm);
            CheckCertReqMsgWithArchiveControl(rsaKeyPair, rsaKeyPair.Private,
                new CertificateRequestMessage(crm.GetEncoded()));
        }

        [Test]
        public void BasicMessageWithArchiveControlJVMGenerated()
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(
                Hex.Decode("305c300d06092a864886f70d0101010500034b003048024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b3070203010001"));
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(
                Hex.Decode("30820154020100300d06092a864886f70d01010105000482013e3082013a020100024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b307020301000102400831deacfe21a9331902d7f648e1297c563196b00c70971fb439098cb5c1618925bdbac4c66b30f8956660220f326f51e5a1725ce690165154fb62fa14497265022100e54943be1b4951e127f6e79c5ab333cba4b0fff0b5e59328d6393ba98dc0e6c3022100bd6da58ce195146a1d3825ec2a622cf4962da653096bea87fbd9a94db266a66d0221008948bcceeef78f97089ec53ed0efcb6b7b489f7638f32491a6f2cdce4f99d89102204eb1b066d8883054ed12985e863506ec0d3fa5ab356cc99ff876b228ff0639f9022024049aaf39bf9a0ddfbd4caee277d0a9f07d075faae12571176a5c0ca40415c0"));

            CertificateRequestMessage crm = new CertificateRequestMessage(
                Hex.Decode("308202af308202ab0201013071a511300f310d300b0603550403130454657374a65c300d06092a864886f70d0101010500034b003048024100a9a94b7b98dc3daf8cac032a14bd4510832b0e007edbdafc065e328645a35828b8185cdbf73ed495c88436b11a9322965595d2e4c1dd63c3c4d41812f876b3070203010001308202313082022d06092b0601050507050104a082021ea082021a0201003171306f0201003019300f310d300b06035504030c04546573740206016859de5806300d06092a864886f70d0101010500044066f1a72f808908af784b83c07895276104d7c4caaee6090212ce5b27517aec510425b784352b5342c999f844b8796286f10a59807e290f06aa39f8cba86dd6bf308201a0060b2a864886f70d0109100115301d060960864801650304010204104aceaa277cc7974ea2a775ff9db6062580820170c648e70c25c4789d2ff4ed398e5536efb45d2dd8ba76a628ad30bf9596a18337afc0f596f0c18e05fb3fa9944ed9691dae1d9b327b5bbafaaa63efb0e22d675811c27bfb023b80184325fd4b67b3b9e41bf43c5583a86433b230e09a34b61397ddff0eadf10c883fc1f01860e2a56ab4002dcc4d4925c53e09dde0b99928fdf602bce544722155cebd8816e91a411a99feea07695774cd8883034022d57f64e9cd3383c3125c48db2936b7395a22b17910be1f2c0b8650bdb5bd752ffc40fcd30169e5ae3a4ac7ad9cc850e9c17bbcf8e1a1898d0d8be19145c484467b8f1124657a5e08c10fc67416274990cc16d55c9fb76c265dd436b7e803425892297f1a08e4fab8e178874b2b3bf9c749693d609db208e9a3ebbddd26cd6a1b33c0201532170dc6c303e7ac0c42ba0bc54dfb928b228842b6bb08d8dc411d262dabf140a8b5a5c67ea486c1877a2fc000981d54cf2decaf1cfeebcf83134992b09a2b1fe9e02da25b874604b5d8bbd609875ba8"));

            var rsaKeyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            var certTemplate = crm.GetCertTemplate();
            Assert.That(certTemplate.Subject.Equivalent(new X509Name("CN=Test")));
            Assert.That(Arrays.AreEqual(certTemplate.PublicKey.GetEncoded(), spki.GetEncoded()));

            CheckCertReqMsgWithArchiveControl(rsaKeyPair, rsaKeyPair.Private, crm);
            CheckCertReqMsgWithArchiveControl(rsaKeyPair, rsaKeyPair.Private,
                new CertificateRequestMessage(crm.GetEncoded()));
        }

        [Test]
        public void BasicMessageWithOldCertIDControl()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            TestCertBuilder tcb = new TestCertBuilder();
            tcb.PublicKey = rsaKeyPair.Public;
            tcb.Subject = new X509Name("CN=Old Cert");
            tcb.Issuer = new X509Name("CN=Old Cert");
            tcb.NotBefore = DateTime.UtcNow.AddDays(-1);
            tcb.NotAfter = DateTime.UtcNow.AddDays(1);
            tcb.SignatureAlgorithm = "Sha1WithRSAEncryption";

            X509Certificate oldCert = tcb.Build(rsaKeyPair.Private);

            var issuer = oldCert.IssuerDN;
            var serialNumber = oldCert.CertificateStructure.SerialNumber;

            CertificateRequestMessage crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(new OldCertIDControl(issuer, serialNumber))
                .Build();

            CertId expected = new CertId(new GeneralName(issuer), serialNumber);

            CheckCertReqMsgWithOldCertIDControl(crm, expected);
            CheckCertReqMsgWithOldCertIDControl(new CertificateRequestMessage(crm.GetEncoded()), expected);

            Assert.AreEqual(expected, new OldCertIDControl(issuer, serialNumber).Value);
        }

        [Test]
        public void BasicMessageWithProtocolEncrKeyControl()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            CertificateRequestMessage crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(new ProtocolEncrKeyControl(spki))
                .Build();

            CheckCertReqMsgWithProtocolEncrKeyControl(crm, spki);
            CheckCertReqMsgWithProtocolEncrKeyControl(new CertificateRequestMessage(crm.GetEncoded()), spki);
        }

        [Test]
        public void BasicMessageWithPublicationInfoControl()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            SinglePubInfo pubInfo = new SinglePubInfo(SinglePubInfo.x500, new GeneralName(new X509Name("CN=Test CA")));

            CertificateRequestMessage crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(new PkiPublicationInfoControl(new SinglePubInfo[] { pubInfo }))
                .Build();

            CheckCertReqMsgWithPublicationInfoControl(crm, pubInfo);
            CheckCertReqMsgWithPublicationInfoControl(new CertificateRequestMessage(crm.GetEncoded()), pubInfo);

            // asking for no publication at all carries the action on its own
            crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(PkiPublicationInfoControl.DontPublish())
                .Build();

            crm = new CertificateRequestMessage(crm.GetEncoded());

            PkiPublicationInfoControl control = (PkiPublicationInfoControl)crm.GetControl(
                CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo);

            Assert.AreEqual(PkiPublicationInfo.DontPublish, control.PublicationInfo.Action);
            Assert.Null(control.PublicationInfo.GetPubInfos());

            // and "don't care" is the pleasePublish action with no locations
            crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(new PkiPublicationInfoControl((SinglePubInfo[])null))
                .Build();

            crm = new CertificateRequestMessage(crm.GetEncoded());

            control = (PkiPublicationInfoControl)crm.GetControl(CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo);

            Assert.AreEqual(PkiPublicationInfo.PleasePublish, control.PublicationInfo.Action);
            Assert.Null(control.PublicationInfo.GetPubInfos());
        }

        [Test]
        public void BasicMessageWithRegInfo()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            AttributeTypeAndValue regInfoATaV = new AttributeTypeAndValue(CmpObjectIdentifiers.regInfo_utf8Pairs,
                new DerUtf8String("CertType?Server%"));
            AttributeTypeAndValue[] atavArr = new AttributeTypeAndValue[1];
            atavArr[0] = regInfoATaV;

            CertificateRequestMessage crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .SetRegInfo(atavArr)
                .SetProofOfPossessionSignKeySigner(new Asn1SignatureFactory("SHA1WithRSA", rsaKeyPair.Private))
                .Build();

            Assert.That(crm.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(rsaKeyPair.Public)));

            var certTemplate = crm.GetCertTemplate();
            Assert.That(certTemplate.Subject.Equivalent(new X509Name("CN=Test")));
            Assert.That(certTemplate.PublicKey.Equals(spki));

            CertReqMsg certReqMsgAsn1 = crm.ToAsn1Structure();
            Assert.AreEqual(1, certReqMsgAsn1.GetRegInfo().Length);
            Assert.AreEqual(atavArr[0], certReqMsgAsn1.GetRegInfo()[0]);
        }

        [Test]
        public void ECBasicMessageWithArchiveControl()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("EC");
            kpg.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));

            var clientKP = kpg.GenerateKeyPair();
            var serverKP = kpg.GenerateKeyPair();

            var clientPrivateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(clientKP.Private);
            var clientSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(clientKP.Public);

            var serverPrivateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(serverKP.Private);
            var serverSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(serverKP.Public);

            var serverSubject = new X509Name("CN=Test Server");

            TestCertBuilder tcb = new TestCertBuilder();
            tcb.PublicKey = serverKP.Public;
            tcb.Subject = serverSubject;
            tcb.Issuer = serverSubject;
            tcb.NotBefore = DateTime.UtcNow.AddDays(-1);
            tcb.NotAfter = DateTime.UtcNow.AddDays(1);
            tcb.SignatureAlgorithm = "SHA256withECDSA";

            X509Certificate serverCert = tcb.Build(serverKP.Private);

            CertificateRequestMessageBuilder crmBuilder = new CertificateRequestMessageBuilder(BigInteger.One);
            crmBuilder.SetSubject(new X509Name("CN=Test"));
            crmBuilder.SetSubjectPublicKeyInfo(clientSpki);

            var recipientCerts = new List<X509Certificate>() { serverCert };

            crmBuilder.AddControl(
                new PkiArchiveControlBuilder(clientPrivateKeyInfo, new GeneralName(new X509Name("CN=Test")))
                    .AddRecipientGenerator(new KeyAgreeRecipientInfoGenerator(recipientCerts) {
                        KeyAgreementOid = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme,
                        KeyEncryptionOid = NistObjectIdentifiers.IdAes256Wrap,
                        SenderKeyPair = clientKP,
                    })
                    .Build(new CmsContentEncryptorBuilder(NistObjectIdentifiers.IdAes128Cbc).Build())
            );

            CertificateRequestMessage crm = crmBuilder.Build();

            var certTemplate = crm.GetCertTemplate();
            Assert.That(certTemplate.Subject.Equivalent(new X509Name("CN=Test")));
            Assert.That(certTemplate.PublicKey.Equals(clientSpki));

            CheckCertReqMsgWithArchiveControl(clientKP, serverKP.Private, crm);
            CheckCertReqMsgWithArchiveControl(clientKP, serverKP.Private,
                new CertificateRequestMessage(crm.GetEncoded()));
        }

        [Test]
        public void GetControlValue()
        {
            var rsaKeyPair = GenerateRsaKeyPair(512);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaKeyPair.Public);

            CertificateRequestMessage crm = new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetSubjectPublicKeyInfo(spki)
                .AddControl(new ProtocolEncrKeyControl(spki))
                .AddControl(new UnknownControl())
                .Build();

            crm = new CertificateRequestMessage(crm.GetEncoded());

            Assert.AreEqual(spki, crm.GetControlValue(CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey));
            Assert.That(crm.HasControl(UnknownControl.unknownControl));
            Assert.Null(crm.GetControl(UnknownControl.unknownControl));
            Assert.AreEqual(new DerUtf8String("a control this class has no implementation for"),
                crm.GetControlValue(UnknownControl.unknownControl));

            Assert.False(crm.HasControl(CrmfObjectIdentifiers.id_regCtrl_oldCertID));
            Assert.Null(crm.GetControlValue(CrmfObjectIdentifiers.id_regCtrl_oldCertID));
        }

        [Test]
        public void ArchiveControlWithoutEnvelopedData()
        {
            EncryptedValue encValue = new EncryptedValue(null, new AlgorithmIdentifier(NistObjectIdentifiers.IdAes128Cbc),
                new DerBitString(new byte[16]), null, null, new DerBitString(new byte[32]));

            CheckArchiveControlWithoutEnvelopedData(PkiArchiveControl.keyGenParameters,
                new PkiArchiveOptions(new DerOctetString(new byte[8])));
            CheckArchiveControlWithoutEnvelopedData(PkiArchiveControl.archiveRemGenPrivKey,
                new PkiArchiveOptions(true));
            CheckArchiveControlWithoutEnvelopedData(PkiArchiveControl.encryptedPrivKey,
                new PkiArchiveOptions(new EncryptedKey(encValue)));
        }

        [Test]
        public void ProofOfPossessionSigningKeyIncomplete()
        {
            // a signing key POP the builder cannot form must be refused with a CrmfException, not an NRE
            var rsaKeyPair = GenerateRsaKeyPair(512);

            var signer = new Asn1SignatureFactory("SHA1WithRSA", rsaKeyPair.Private);

            string noPublicKey = "signing key proof of possession requires a public key in the certificate template";
            string noAuthInfo = "signing key proof of possession without a subject in the certificate template requires an authInfo sender or PKMAC";

            // no public key, sender set
            CheckIncompleteSigningKeyPop(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(new X509Name("CN=Test"))
                .SetAuthInfoSender(new X509Name("CN=Test"))
                .SetProofOfPossessionSignKeySigner(signer), noPublicKey);

            // no public key, PKMAC set
            CheckIncompleteSigningKeyPop(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetAuthInfoPKMacBuilder(new PKMacBuilder(), "fred".ToCharArray())
                .SetProofOfPossessionSignKeySigner(signer), noPublicKey);

            // no public key, no subject, no authInfo
            CheckIncompleteSigningKeyPop(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetProofOfPossessionSignKeySigner(signer), noPublicKey);

            // public key, no subject, neither sender nor PKMAC
            CheckIncompleteSigningKeyPop(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetPublicKey(rsaKeyPair.Public)
                .SetProofOfPossessionSignKeySigner(signer), noAuthInfo);
        }

        private void CheckArchiveControlWithoutEnvelopedData(int archiveType, PkiArchiveOptions options)
        {
            CheckArchiveControlWithoutEnvelopedData(archiveType, new PkiArchiveControl(options));
            CheckArchiveControlWithoutEnvelopedData(archiveType,
                new PkiArchiveControl(PkiArchiveOptions.GetInstance(Asn1Object.FromByteArray(options.GetEncoded()))));
        }

        private void CheckArchiveControlWithoutEnvelopedData(int archiveType, PkiArchiveControl archiveControl)
        {
            Assert.AreEqual(archiveType, archiveControl.ArchiveType);
            Assert.False(archiveControl.IsEnvelopedData());

            try
            {
                archiveControl.GetEnvelopedData();
                Assert.Fail("no exception");
            }
            catch (CrmfException e)
            {
                Assert.AreEqual(e.Message, "archive control does not contain enveloped data");
            }
        }

        private void CheckCertReqMsgWithArchiveControl(AsymmetricCipherKeyPair kp,
            AsymmetricKeyParameter recipientPrivateKey, CertificateRequestMessage certReqMessage)
        {
            PkiArchiveControl archiveControl = (PkiArchiveControl)certReqMessage.GetControl(
                CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions);
            Assert.AreEqual(PkiArchiveControl.encryptedPrivKey, archiveControl.ArchiveType, "Archive type");

            Assert.True(archiveControl.IsEnvelopedData());
            RecipientInformationStore recips = archiveControl.GetEnvelopedData().GetRecipientInfos();

            var collection = recips.GetRecipients();
            Assert.AreEqual(1, collection.Count);

            RecipientInformation recipientInformation = collection[0];
            if (recipientInformation is KeyAgreeRecipientInformation keyAgreeRI)
            {
            }
            else if (recipientInformation is KeyTransRecipientInformation keyTransRI)
            {
            }
            else
            {
                Assert.Fail();
            }

            EncKeyWithID encKeyWithID = EncKeyWithID.GetInstance(recipientInformation.GetContent(recipientPrivateKey));

            Assert.True(encKeyWithID.HasIdentifier);
            Assert.False(encKeyWithID.IsIdentifierUtf8String); // GeneralName at this point.

            Assert.True(X509Name.GetInstance(GeneralName.GetInstance(encKeyWithID.Identifier).Name).Equivalent(new X509Name("CN=Test")), "Name");

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
            Assert.That(Arrays.AreEqual(privateKeyInfo.GetEncoded(), encKeyWithID.PrivateKey.GetEncoded()), "Private Key");
        }

        private void CheckCertReqMsgWithOldCertIDControl(CertificateRequestMessage certReqMsg, CertId expected)
        {
            Assert.That(certReqMsg.HasControl(CrmfObjectIdentifiers.id_regCtrl_oldCertID));

            OldCertIDControl control = (OldCertIDControl)certReqMsg.GetControl(CrmfObjectIdentifiers.id_regCtrl_oldCertID);

            Assert.AreEqual(CrmfObjectIdentifiers.id_regCtrl_oldCertID, control.Type);
            Assert.AreEqual(expected, control.CertId);
        }

        private void CheckCertReqMsgWithProtocolEncrKeyControl(CertificateRequestMessage certReqMsg,
            SubjectPublicKeyInfo publicKeyInfo)
        {
            Assert.That(certReqMsg.HasControl(CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey));

            ProtocolEncrKeyControl protocolEncrKeyControl = (ProtocolEncrKeyControl)certReqMsg.GetControl(
                CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey);

            Assert.AreEqual(CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey, protocolEncrKeyControl.Type);
            Assert.AreEqual(publicKeyInfo, protocolEncrKeyControl.Value);
        }

        private void CheckCertReqMsgWithPublicationInfoControl(CertificateRequestMessage certReqMsg,
            SinglePubInfo pubInfo)
        {
            Assert.That(certReqMsg.HasControl(CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo));

            PkiPublicationInfoControl control = (PkiPublicationInfoControl)certReqMsg.GetControl(
                CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo);

            Assert.AreEqual(CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo, control.Type);
            Assert.AreEqual(PkiPublicationInfo.PleasePublish, control.PublicationInfo.Action);
            Assert.AreEqual(1, control.PublicationInfo.GetPubInfos().Length);
            Assert.AreEqual(pubInfo, control.PublicationInfo.GetPubInfos()[0]);
        }

        private void CheckIncompleteSigningKeyPop(CertificateRequestMessageBuilder certReqBuild, string expectedMessage)
        {
            try
            {
                certReqBuild.Build();
                Assert.Fail("no exception");
            }
            catch (CrmfException e)
            {
                Assert.AreEqual(expectedMessage, e.Message);
            }
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int strength)
        {
            RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), strength, 100));
            return kpg.GenerateKeyPair();
        }

        private class UnknownControl : IControl
        {
            internal static readonly DerObjectIdentifier unknownControl = new DerObjectIdentifier("1.2.3.4.5.6.7.8.9");

            public DerObjectIdentifier Type => unknownControl;

            public Asn1Encodable Value => new DerUtf8String("a control this class has no implementation for");
        }
    }
}
