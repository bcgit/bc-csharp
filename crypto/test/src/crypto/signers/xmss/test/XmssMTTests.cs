using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    using XmssMT = XmssHarnessTests.XmssMT;

    /// <summary>Test cases for the XMSS^MT signer, over the harness key holder.</summary>
    /// <remarks>
    /// The signature vectors are compared byte for byte; those longer than 4096 hex characters are loaded from
    /// <c>crypto/test/data/xmss/XmssMTTests.*.hex</c>.
    /// </remarks>
    [TestFixture]
    public class XmssMTTests
    {
        [Test]
        public void TestGenKeyPairSha256()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 4, new Sha256Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] privateKey = xmssMT.ExportPrivateKey();
            byte[] publicKey = xmssMT.ExportPublicKey();
            string expectedPrivateKey =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000ea874c176936e8456c1650167a7e900e546f923382f9bc5a92a2df07d5080aee";
            string expectedPublicKey =
                "00000002ea874c176936e8456c1650167a7e900e546f923382f9bc5a92a2df07d5080aee000000000000000000000000"
                    + "0000000000000000000000000000000000000000";
            byte[] strippedPrivateKey = Arrays.CopyOfRange(privateKey, 0, Hex.Decode(expectedPrivateKey).Length);

            Assert.AreEqual(Hex.Decode(expectedPrivateKey), strippedPrivateKey);
            Assert.AreEqual(Hex.Decode(expectedPublicKey), publicKey);
            Assert.AreEqual(NistObjectIdentifiers.IdSha256, parameters.TreeDigestOid);
        }

        [Test]
        public void TestGenKeyPairSha512()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 4, new Sha512Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] privateKey = xmssMT.ExportPrivateKey();
            byte[] publicKey = xmssMT.ExportPublicKey();
            string expectedPrivateKey =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "0000007571b70ae5442f1e352d3e02cf0016ec96b23e51ff8e43c9ae0b758d4fd37bb82a261908bac5a69ddb75c7d5b6"
                    + "d966d7210028b020667a104feaab7cb2ae0278";
            string expectedPublicKey =
                "0000000a7571b70ae5442f1e352d3e02cf0016ec96b23e51ff8e43c9ae0b758d4fd37bb82a261908bac5a69ddb75c7d5"
                    + "b6d966d7210028b020667a104feaab7cb2ae027800000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000";
            byte[] strippedPrivateKey = Arrays.CopyOfRange(privateKey, 0, Hex.Decode(expectedPrivateKey).Length);

            Assert.AreEqual(Hex.Decode(expectedPrivateKey), strippedPrivateKey);
            Assert.AreEqual(Hex.Decode(expectedPublicKey), publicKey);
            Assert.AreEqual(NistObjectIdentifiers.IdSha512, parameters.TreeDigestOid);
        }

        [Test]
        public void TestSignSha256()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] message = new byte[1024];
            byte[] sig1 = xmssMT.Sign(message);
            byte[] sig2 = xmssMT.Sign(message);
            byte[] sig3 = xmssMT.Sign(message);

            Assert.AreEqual("e7d2545815a745e4491723dfbb5954873383262287ceea6c8f0816a283dc487d",
                XmssTestData.Sha256Hex(sig1));
            Assert.AreEqual("e3a7295c770390dbb103d0bccab8250dc971405fc54375d1bea13d77f5c1c0f6",
                XmssTestData.Sha256Hex(sig2));
            Assert.AreEqual("2d0870f3f334779b8eff79f19e722e6770b7f1c9d4d3d5236acf3246e14b2b62",
                XmssTestData.Sha256Hex(sig3));
        }

        /// <summary>The SHA-256 of each of the 64 signatures of the bc-java vector, in index order.</summary>
        private static readonly string[] SignSha256Complete1 = new string[]
        {
            "2d015cd8b94673b37e1500ee18f69cce56e7ef8a93641517fb66461193f08d45",
            "6af710bce322d4e0d7a5eb85f7b74491bbfe7cfb97a400068d5e5c3d4df79802",
            "81f17aff95228e562b8046ac476a43fd54a77860f1c4337c9391c77da3b94abc",
            "7082dba61b9a99aa6c6b6905b2cef3e545e2dfdc7d5fa7a6d44a724725c97299",
            "f0b139ef5df4e307a638ce3f0df8a4b3e5ef1b09f73523756474923c8ed902a5",
            "dfd51aedd3d6854c46cbed72f127da8b3c6c7413f3bdc3af0f58049cc714499a",
            "b7634aeb3f78fba14295c222d275fd6895dc3ab090a5bd57569e102a997d9b63",
            "c72e14c607258d6423f91f23c33d281c99a54727a526bbfcf5266d783b8aa847",
            "be1c505ca1937c955f2546d97ea49cc7388e0d50dd7f42a86742bd2021d3fc12",
            "01e62b328571c5c113b75a73944b0fbab92ceeb4b7f787259e18605a1471346a",
            "2dedeb6cce87adb2a301b404a0bf0df3f45d78e0d87759330af648eb02776e92",
            "6e1e19f78d6f686637538f3a964bff2d1e1e97c39f595dc9b1f13622d9197b30",
            "33643352187af4dd6dcf164d55f9768b61cc3dcd9fe20f9433d64181a83de9d3",
            "f5f872d8326d681a0461647eed3d0393491a801dae19ba6e23dec4946d3fd43f",
            "e59477e0442ee8943684821e278746d763c1596208a1ce577b73a5b2b053295a",
            "d218ffa8f8f647248fa5125025e3b0f43a876fd1a9b322de7deb44545037c164",
            "b0994a6eef53c4384585bc3bc6229d47e99206d269a9c9b2a7076e9d9c0680f6",
            "bf08209a2b8316ff8c9bb1e76e0ed79177671f3a6d7e6a279b8268c536922edc",
            "a3f283aa3a189c4a175e66599407e39c231d2db24646f87ff8683423d377d2f3",
            "8fd51ad772b7dc0b2e18b6ba20b0436941259a59f1765ea1a9dbe7490298034d",
            "c5d4f8d36fe8579f688e7ef2b59b260f99823aa9b85eb08e69a3cddf72d980c3",
            "01d7be2d9653a23ee5efed0d5c3b17ebb530d69c66007adb580d2203501dcdda",
            "5fc1d5ec5bd2674b73fd28aec7ed68bc42ce0671395c434cdcda2e7bb1020ce9",
            "05c761aa66b9af91e9af5a2c0beea7f9603e05bf0530a54c6a540fadb215fd55",
            "b0303739becba63121f4bc831232e777fcd21a5167b5e28c0a878eb971b4c165",
            "9643624b29bf00336eccaf5c2c07dcf8757f4d958b1477a63b390ad925521f74",
            "28da5253a76fc0ae72f0e840eacb8bb13911c161ef3b188d8056e3d364a6aa4e",
            "2203275faeb64c755304490af1f6561c66327f7dac505bd70095de98cbd4f144",
            "4296edbf94dd957dd05bdd86475e3ccd7846dbc956f9e3fec8552e5b7e27c8b1",
            "dba95e8bbc5905f1514d580eb6a3257033bd53e853573c67d996ca3a05118d94",
            "21ed6313c929d14809bc4d792bc60aefe7754a148ee3f557eeae997a18dcfeb3",
            "6569e2ac0e668ce97e01cea45ba8e4be65d459d2670442f10858b2bad0790e1c",
            "6cef684a0954976df92e088a934dca9e1e4f47c4575f6027e0a16e748bb052bf",
            "1020bd86b40614b4a4f0c52cd37db9c43ed7e7b98c19c92673f8f53542f2a626",
            "6384fcf2e2c270314ccc4d0cf3f8e23b86c023cc3dfd0bf2d8831bfff5a7784a",
            "9b4db0543aef68e184477b5854a68563e217d4b54a5da82f95139693532c5c0f",
            "12d1548fa44955a60e76b7b670a9268ca142be74d8872115b8b0a2cd6dfb1f7b",
            "03ff1476357fc1958a4b102d578f7c8c6553931fb68219216521c582815e62a3",
            "27833d8f0dae36d8a1700a872c967541f0eb854ee8aa8f896a5589e0ae53895c",
            "2fee54edf768899143fbf766fc1bd8650bf185547919efa654b6811d6e31641a",
            "88df408b511782a17f1b3cf41816066782574ef86c18f19371aaa061ea8c2987",
            "136a19636856b4266f2d98bc90271e767d26f9d363d62b879746681f488e6445",
            "c5a0d224b75e693d136285685de753f7a1d3c421473ac3cb50742c3583ae7824",
            "152de1a0e530f07253c544b1f4726c74c0f5005e16dd07102cab33b55ba35a8e",
            "9a713ed1b0c6c8946d61f02e67a10b7550230959f932a9711bc86d0909402c84",
            "2cac04637cbc3a92f4d7194a7f025dd9cf1b8f2c5e665f2dcc83a46155391be4",
            "fe6ba01ad6ca01ec30146f1c4f17b5ce9a412e3d42ae32150dd404777b416ecb",
            "6eb85c9e5cb6f8adeae36bc4878191679d0ca6fb6c1a1526f89fc07138090a97",
            "ee40af70c9dfb425d41e3cf0b0d7eb317837a148017d7693dffd2387333f73f2",
            "d358224af3ce5dc3e8673ceb2643690d0d0b07a91dbe8eb79534afa59dcf7819",
            "e6792298b5abae2bc012dc65a7777497690716c9a13561ea28626b696944bab9",
            "1df3d3ebcc8669586734ba27e4c54f2dd6b25c169b20eac763111a8ab4ca6d0f",
            "c9520faee9a946d96eb5aba5e0f4a3366bd766f0f65f8f39407e48651006117c",
            "7a4deefd1e7a3df5e11d2351e494b0bbd45f6c1f2a5b4d8f9a94530cb2362a65",
            "afba5f03f006d2c88322933365e1bfbe40c9c2e23632bfe76ce9d57e2d6881e4",
            "12169e875bce98a9497fc17e553389c0b75ced0636c16e93fde14dbc90103618",
            "b304d4f66863cf6a525ff6a768635594ec08fde304b1871050ecec4b234b71c7",
            "08e6cdfa5d79602db236875b4eb25940806f6933f85ec7474ae44fc719cb20fe",
            "6e255996c73f0d69aa6f98d82cb02525b6e9fc720e875ea65ae8ee004d80d959",
            "ef89834320de44d0d85e47726faf9f5fbdeb94205c3e6b1de8939aeed0de794d",
            "196a84507f762a8ce58541367f2e5ebdfbffde90dbe030eb8c9be2d4ceafe8ea",
            "f7b9fea688ce638e4a7bf1df521b9d2ceb4266931db18f005a698375bdb6d034",
            "8ceabf2d5a7b7cf2b3d7de1de93861a61ff7ab8e681231555a8ed6be0fe3d196",
            "2d5896c29b3f6ab5eafd12a4ece67e74288bdfe278f05f3eda4ec8709138beb8",
        };

        /// <summary>Every index of a 6/2 hypertree, and the refusal past the last one.</summary>
        [Test]
        public void TestSignSha256Complete1()
        {
            CheckSignComplete(SignSha256Complete1, 6, 2);
        }

        /// <summary>Every index of a 4/2 hypertree, and the refusal past the last one.</summary>
        [Test]
        public void TestSignSha256Complete2()
        {
            CheckSignComplete(SignSha256Complete2, 4, 2);
        }

        /// <summary>The SHA-256 of each of the 16 signatures of the bc-java vector, in index order.</summary>
        private static readonly string[] SignSha256Complete2 = new string[]
        {
            "5f9817afed498a95db21aed606bdd9f2ecb21a49931942e3f97ec113c8886cac",
            "ba51091505eba3679fab45948db4d33965a065638c4aa7f6eaecf94273245d43",
            "5c7b9cfe6809b9db9c7a2d41312509cf2186dc2ace529e9e7d672433c1fde0d0",
            "f9867763542db2ac745ee8bb492f47829ba77b798bc5805358ee550384085964",
            "c158079233aaddebf427d968d052c206e55671b224d17e2cbcbf0c97ff08bbd8",
            "6460d806c6771368d4df0509a258ff5497d5993fe2bde77ed20d6cf7d091e402",
            "5960607f96a280717541d862f55cc7fba43a6383093066e01dd0c2d95df7f426",
            "b3676401d4a0d127d35d31c260703343cc5a7c680885587710517bc1834fb1a7",
            "1a76f91b36a4dbf7a341e7ee46fc343ca21ecb157d1e00007f17516eae736936",
            "65b80c1c3f01ecd57497e057dcdd29f66c39ff11989cf6c5711f6fffc84fb434",
            "8acc16d9ea9dd5e0d9fb6c935a8b51d3ea6dac4084f9c43572f19877e75e72db",
            "d8c2578c5f06bcb583d42846f8a1e144cae29489541ba909149698c8e8e6e256",
            "2cfefd5eba0187cfcf187f344cafe73ae36de1c3959840789aa247d69d8492f6",
            "5deba2320abf45c5fc4a5ef96b0eadc5bcb4ec542f5f33c83280ca13f5aa8597",
            "9b22615f7351870f5ad3c3350ee65c8028abb044e3d682de4bb524bb24b837e4",
            "51ecd4f099720825532184101307d68b4e1ea0fb225e78b20ceea6c3c8c59d7e",
        };

        private static void CheckSignComplete(string[] expected, int height, int layers)
        {
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            for (int i = 0; i < (1 << height); i++)
            {
                byte[] signature = xmssMT.Sign(new byte[1024]);
                Assert.AreEqual(expected[i], XmssTestData.Sha256Hex(signature), "signature " + i);
            }

            Assert.Throws<ExhaustedPrivateKeyException>(() => xmssMT.Sign(new byte[1024]));
        }

        /// <summary>
        /// The SHA-256 of each bc-java signature <see cref="TestSignSha256Complete3"/> compares, in the order of its
        /// indices.
        /// </summary>
        private static readonly string[] SignSha256Complete3 = new string[]
        {
            "ec5c53aac35b09a6497d26f4d22ee875f93f65b124f432ef0ec81a9f96a6ed76",
            "fec881e0538b5bd581a96390592baed84af0b160ff41056ce2ad3e406b9f3c59",
            "d313af32db87c020f53f822695df0291b5601cc2f58e5765051c7a38d0d55a18",
            "1f700b57d80f43b5ba5c2aedc3283c794c8dfb68c1dae694b1c6a2ebefc68cb6",
            "57535fee0b97b983c9c65119dc959c382c52cea5da5ac2195e961435defcd3d0",
            "546b1e273a31837a16898143e60ac30426d1ff1af205a51b41e6a5763a1c5248",
            "73e0e23055d7760004f1c98d7a788786f07a237f3a56d442d896afcef0bd86fa",
            "d3584881e6c5e3bf73663b6787454d80707dff8c9f7dcc8973f69c59d6912c3d",
            "6e9af9f1f25f20381e4d94f40918d4c6119319c59d0587a0f5591705f9c1a9c5",
            "0ff7b220cde7f831c95631b753c2d66610fc19f117ffc5414fbf95b9083e4a83",
        };

        /// <summary>Every index of a 10/5 hypertree, ten of them against known answers.</summary>
        [Test]
        [Explicit] // slow: ~79s
        public void TestSignSha256Complete3()
        {
            int[] indices = { 0x0006, 0x0023, 0x014c, 0x01dd, 0x028d, 0x0320, 0x0338, 0x03e9, 0x03fe, 0x03ff };
            int height = 10;
            int layers = 5;
            XmssMTParameters parameters = new XmssMTParameters(height, layers, new Sha256Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            int checkedCount = 0;
            for (int i = 0; i < (1 << height); i++)
            {
                byte[] signature = xmssMT.Sign(new byte[1024]);
                int k = Array.IndexOf(indices, i);
                if (k >= 0)
                {
                    Assert.AreEqual(SignSha256Complete3[k], XmssTestData.Sha256Hex(signature), "signature " + i);
                    checkedCount++;
                }
            }
            Assert.AreEqual(indices.Length, checkedCount);

            Assert.Throws<ExhaustedPrivateKeyException>(() => xmssMT.Sign(new byte[1024]));
        }

        [Test]
        public void TestSignSha512()
        {
            XmssMTParameters parameters = new XmssMTParameters(6, 3, new Sha512Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] message = new byte[1024];
            byte[] sig1 = xmssMT.Sign(message);
            byte[] sig2 = xmssMT.Sign(message);
            byte[] sig3 = xmssMT.Sign(message);

            Assert.AreEqual("fcf98791ef99fcd7e1d223f5cd6ba22c2397102378a06a07eaf5edb1fe36021e",
                XmssTestData.Sha256Hex(sig1));
            Assert.AreEqual("37df71c7e833d2dbb51760e98cbeeb42aa37305deca22404de4a5275eb3af23c",
                XmssTestData.Sha256Hex(sig2));
            Assert.AreEqual("cc0b1fc81067de92470f50e5d65e4d63f514a99bde78652ae8bf15a9d114a0f4",
                XmssTestData.Sha256Hex(sig3));
        }

        [Test]
        public void TestVerifySignatureSha256()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();

            byte[] msg1 = SecureRandom.GetNextBytes(new SecureRandom(), 1024);

            for (int i = 0; i < 3; i++)
            {
                byte[] publicKey = xmssMT.ExportPublicKey();
                xmssMT.Sign(msg1);
                byte[] signature = xmssMT.Sign(msg1);
                Assert.IsTrue(xmssMT.VerifySignature(msg1, signature, publicKey));

                msg1[0] ^= 0xff;
                Assert.IsFalse(xmssMT.VerifySignature(msg1, signature, publicKey));
            }
        }

        [Test]
        public void TestVerifySignerSha256()
        {
            CheckVerifySigner(new XmssMTParameters(20, 10, new Sha256Digest()));
        }

        [Test]
        public void TestVerifySignatureSha512()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha512Digest());
            XmssMT xmssMT = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT.GenerateKeys();
            byte[] msg1 = new byte[1024];

            for (int i = 0; i < 3; i++)
            {
                byte[] publicKey = xmssMT.ExportPublicKey();
                xmssMT.Sign(msg1);
                byte[] signature = xmssMT.Sign(msg1);
                Assert.IsTrue(xmssMT.VerifySignature(msg1, signature, publicKey));

                byte[] msg2 = new byte[1024];
                msg2[0] = 0x01;
                Assert.IsFalse(xmssMT.VerifySignature(msg2, signature, publicKey));
            }
        }

        [Test]
        public void TestVerifySignerSha512()
        {
            CheckVerifySigner(new XmssMTParameters(20, 10, new Sha512Digest()));
        }

        private static void CheckVerifySigner(XmssMTParameters parameters)
        {
            XmssMTKeyPairGenerator xmssMT = new XmssMTKeyPairGenerator();

            xmssMT.Init(new XmssMTKeyGenerationParameters(new XmssHarnessTests.NullPrng(), parameters));

            AsymmetricCipherKeyPair kp = xmssMT.GenerateKeyPair();

            byte[] msg1 = SecureRandom.GetNextBytes(new SecureRandom(), 1024);

            XmssMTSigner signer = new XmssMTSigner();

            AsymmetricKeyParameter privateKey = kp.Private;

            for (int i = 0; i < 3; i++)
            {
                signer.Init(true, privateKey);

                byte[] signature = XmssHarnessTests.Sign(signer, msg1);

                privateKey = signer.GetUpdatedPrivateKey();

                signer.Init(false, kp.Public);

                Assert.IsTrue(XmssHarnessTests.Verify(signer, msg1, signature));

                msg1[0] ^= 0xff;

                Assert.IsFalse(XmssHarnessTests.Verify(signer, msg1, signature));
            }
        }

        [Test]
        public void TestImportKeysSha256()
        {
            CheckImportKeys(new XmssMTParameters(20, 10, new Sha256Digest()));
        }

        [Test]
        public void TestImportKeysSha512()
        {
            CheckImportKeys(new XmssMTParameters(20, 10, new Sha512Digest()));
        }

        private static void CheckImportKeys(XmssMTParameters parameters)
        {
            XmssMT xmssMT1 = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmssMT1.GenerateKeys();
            byte[] msg1 = new byte[1024];
            byte[] msg2 = new byte[2048];
            byte[] msg3 = new byte[3096];
            Arrays.Fill(msg1, 0xaa);
            Arrays.Fill(msg2, 0xbb);
            Arrays.Fill(msg3, 0xcc);
            byte[] signature1 = xmssMT1.Sign(msg1);
            byte[] signature2 = xmssMT1.Sign(msg2);
            byte[] exportedPrivateKey = xmssMT1.ExportPrivateKey();
            byte[] exportedPublicKey = xmssMT1.ExportPublicKey();
            byte[] publicKey = xmssMT1.ExportPublicKey();
            byte[] signature3 = xmssMT1.Sign(msg3);

            XmssMT xmssMT2 = new XmssMT(parameters, new XmssHarnessTests.NullPrng());

            xmssMT2.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] signature4 = xmssMT2.Sign(msg3);
            Assert.IsTrue(Arrays.AreEqual(signature3, signature4));
            xmssMT2.GenerateKeys();
            Assert.IsTrue(xmssMT2.VerifySignature(msg1, signature1, publicKey));
            Assert.IsTrue(xmssMT2.VerifySignature(msg2, signature2, publicKey));
            Assert.IsTrue(xmssMT2.VerifySignature(msg3, signature3, publicKey));
            Assert.IsFalse(xmssMT2.VerifySignature(msg1, signature3, publicKey));
            Assert.IsFalse(xmssMT2.VerifySignature(msg2, signature3, publicKey));
        }

        [Test]
        public void TestRandom()
        {
            XmssMTParameters parameters = new XmssMTParameters(20, 10, new Sha512Digest());
            XmssMT xmss1 = new XmssMT(parameters, new XmssHarnessTests.NullPrng());
            xmss1.GenerateKeys();
            byte[] publicKey = xmss1.ExportPublicKey();
            byte[] message = new byte[1024];

            for (int i = 0; i < 5; i++)
            {
                xmss1.Sign(message);
            }
            byte[] signature = xmss1.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(publicKey, xmss1.ExportPublicKey()));
            xmss1.VerifySignature(message, signature, publicKey);
            Assert.IsTrue(Arrays.AreEqual(publicKey, xmss1.ExportPublicKey()));
            xmss1.Sign(message);
            byte[] privateKey7 = xmss1.ExportPrivateKey();
            xmss1.VerifySignature(message, signature, publicKey);
            Assert.IsTrue(Arrays.AreEqual(privateKey7, xmss1.ExportPrivateKey()));
            byte[] signature7 = xmss1.Sign(message);

            xmss1.ImportState(privateKey7, publicKey);

            byte[] signature7AfterImport = xmss1.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(signature7AfterImport, signature7));

            XmssMTParameters params2 = new XmssMTParameters(20, 10, new Sha512Digest());
            XmssMT xmss2 = new XmssMT(params2, new XmssHarnessTests.NullPrng());
            Assert.IsTrue(xmss2.VerifySignature(message, signature7, publicKey));
            Assert.IsTrue(xmss2.VerifySignature(message, signature, publicKey));

            XmssMT xmss3 = new XmssMT(parameters, new XmssHarnessTests.NullPrng());

            xmss3.ImportState(privateKey7, publicKey);

            byte[] signatureAgain = xmss3.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(signatureAgain, signature7));
        }

        [Test]
        public void TestPublicSeed()
        {
            byte[] message = new byte[1024];
            XmssMTParameters params1 = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMT mt1 = new XmssMT(params1, new SecureRandom());
            mt1.GenerateKeys();
            byte[] publicKey1 = mt1.ExportPublicKey();
            byte[] signature1 = mt1.Sign(message);

            XmssMTParameters params2 = new XmssMTParameters(20, 10, new Sha256Digest());
            XmssMT mt2 = new XmssMT(params2, new XmssHarnessTests.NullPrng());
            mt2.GenerateKeys();
            byte[] publicKey2 = mt2.ExportPublicKey();
            byte[] privateKey2 = mt2.ExportPrivateKey();
            byte[] signature2 = mt2.Sign(message);

            mt2.ImportState(privateKey2, publicKey2);

            Assert.IsTrue(mt2.VerifySignature(message, signature1, publicKey1));
            byte[] signature3 = mt2.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(signature2, signature3));
        }

        [Test]
        public void TestBdsImport()
        {
            XmssMTParameters parameters = new XmssMTParameters(10, 5, new Sha256Digest());
            XmssMT xmss = new XmssMT(parameters, new SecureRandom());
            xmss.GenerateKeys();
            xmss.Sign(new byte[1024]);
            byte[] exportedPrivateKey = xmss.ExportPrivateKey();
            byte[] exportedPublicKey = xmss.ExportPublicKey();

            xmss.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] sig1 = xmss.Sign(new byte[1024]);

            xmss.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] sig2 = xmss.Sign(new byte[1024]);
            Assert.IsTrue(Arrays.AreEqual(sig1, sig2));
            try
            {
                xmss.ImportState(exportedPrivateKey, exportedPublicKey);
            }
            catch (Exception)
            {
            }
            xmss.Sign(new byte[1024]);
            byte[] sig3 = xmss.Sign(new byte[1024]);
            Assert.IsFalse(Arrays.AreEqual(sig1, sig3));
            Assert.Throws<ArgumentNullException>(() => xmss.ImportState(null, exportedPublicKey));
            Assert.Throws<ArgumentNullException>(() => xmss.ImportState(exportedPrivateKey, null));
        }

        [Test]
        [Explicit] // slow: ~28s
        public void TestSignVerifySP800208_Sha256_192()
        {
            CheckSignVerifySP800208(0x00000021, 24);
        }

        [Test]
        [Explicit] // slow: ~52s
        public void TestSignVerifySP800208_Shake256_256()
        {
            CheckSignVerifySP800208(0x00000029, 32);
        }

        [Test]
        [Explicit] // slow: ~39s
        public void TestSignVerifySP800208_Shake256_192()
        {
            CheckSignVerifySP800208(0x00000031, 24);
        }

        private static void CheckSignVerifySP800208(int oid, int n)
        {
            XmssMTParameters parameters = XmssMTParameters.LookupByOid(oid);
            Assert.IsNotNull(parameters);
            Assert.AreEqual(n, parameters.TreeDigestSize);
            Assert.AreEqual(20, parameters.Height);
            Assert.AreEqual(2, parameters.Layers);

            XmssMT xmssMT = new XmssMT(parameters, new SecureRandom());
            xmssMT.GenerateKeys();

            byte[] msg = SecureRandom.GetNextBytes(new SecureRandom(), 1024);

            byte[] publicKey = xmssMT.ExportPublicKey();
            byte[] signature = xmssMT.Sign(msg);

            Assert.IsTrue(xmssMT.VerifySignature(msg, signature, publicKey));

            msg[0] ^= 0xff;
            Assert.IsFalse(xmssMT.VerifySignature(msg, signature, publicKey));
        }

        [Test]
        [Explicit] // slow: ~33s
        public void TestSignerSP800208_Sha256_192()
        {
            CheckSignerSP800208(0x00000021);
        }

        [Test]
        [Explicit] // slow: ~51s
        public void TestSignerSP800208_Shake256_256()
        {
            CheckSignerSP800208(0x00000029);
        }

        [Test]
        [Explicit] // slow: ~39s
        public void TestSignerSP800208_Shake256_192()
        {
            CheckSignerSP800208(0x00000031);
        }

        private static void CheckSignerSP800208(int oid)
        {
            XmssMTParameters parameters = XmssMTParameters.LookupByOid(oid);
            XmssMTKeyPairGenerator kpGen = new XmssMTKeyPairGenerator();
            kpGen.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            byte[] msg = SecureRandom.GetNextBytes(new SecureRandom(), 1024);

            XmssMTSigner signer = new XmssMTSigner();
            signer.Init(true, kp.Private);
            byte[] signature = XmssHarnessTests.Sign(signer, msg);

            signer.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(signer, msg, signature));

            msg[0] ^= 0xff;
            Assert.IsFalse(XmssHarnessTests.Verify(signer, msg, signature));
        }

        /// <summary>
        /// A signature cut short, or with any one of a spread of bits flipped, is reported through the signer as one
        /// that does not verify, rather than raised.
        /// </summary>
        [Test]
        public void SignerRejectsTruncatedAndBitFlippedSignatures()
        {
            XmssMTKeyPairGenerator kpGen = new XmssMTKeyPairGenerator();

            kpGen.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            byte[] msg = new byte[]{ 1, 2, 3 };

            XmssMTSigner signer = new XmssMTSigner();
            signer.Init(true, kp.Private);
            byte[] sig = XmssHarnessTests.Sign(signer, msg);

            XmssMTSigner verifier = new XmssMTSigner();
            verifier.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, msg, sig));

            Assert.IsFalse(XmssHarnessTests.Verify(verifier, msg, Arrays.CopyOf(sig, sig.Length - 1)), "truncated");
            Assert.IsFalse(XmssHarnessTests.Verify(verifier, msg, Arrays.CopyOf(sig, sig.Length / 2)), "halved");

            // the index byte, the randomizer, a WOTS+ chain of the bottom layer, and the top layer's auth path
            int[] offsets = { 0, 1, sig.Length / 3, sig.Length / 2, sig.Length - 1 };
            foreach (int offset in offsets)
            {
                byte[] flipped = Arrays.Clone(sig);
                flipped[offset] ^= 0x01;
                Assert.IsFalse(XmssHarnessTests.Verify(verifier, msg, flipped), "bit flipped at byte " + offset);
            }

            // and the untouched signature still verifies afterwards: nothing above left the verifier in a bad state
            Assert.IsTrue(XmssHarnessTests.Verify(verifier, msg, sig));
        }

        /// <summary>
        /// A signer re-initialised for signing no longer verifies against the public key of an earlier verification
        /// init; a verification init leaves the private key in place, so sign, verify, then collect the advanced
        /// state still works; and a signer that was never initialised says so for both directions.
        /// </summary>
        [Test]
        public void TestReInitClearsThePublicKey()
        {
            XmssMTKeyPairGenerator kpGen = new XmssMTKeyPairGenerator();

            kpGen.Init(new XmssMTKeyGenerationParameters(new SecureRandom(),
                new XmssMTParameters(4, 2, new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            byte[] msg = Hex.Decode("54686520706f77657273206e6f742064656c65676174656420746f2074686520");

            XmssMTSigner signer = new XmssMTSigner();

            signer.Init(false, kp.Public);
            signer.Init(true, kp.Private);

            byte[] sig = XmssHarnessTests.Sign(signer, msg);

            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssHarnessTests.Verify(signer, msg, sig));
            Assert.AreEqual("signer not initialized for verification", e.Message);

            signer.Init(false, kp.Public);

            Assert.IsTrue(XmssHarnessTests.Verify(signer, msg, sig));

            signer.Init(true, kp.Private);
            XmssHarnessTests.Sign(signer, msg);
            signer.Init(false, kp.Public);

            Assert.IsNotNull(signer.GetUpdatedPrivateKey());

            signer.Init(false, kp.Public);

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Sign(signer, msg));
            Assert.AreEqual("signer not initialized for signature generation", e.Message);

            // a signer that was never initialised at all reports that rather than returning false
            XmssMTSigner fresh = new XmssMTSigner();

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Verify(fresh, msg, sig));
            Assert.AreEqual("signer not initialized for verification", e.Message);

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Sign(fresh, msg));
            Assert.AreEqual("signer not initialized for signature generation", e.Message);
        }
    }
}
