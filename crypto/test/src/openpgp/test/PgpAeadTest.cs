using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpAeadTest
    {
        private static readonly byte[] PlainText = Strings.ToByteArray("Hello, world!");
        private static readonly char[] Password = "password".ToCharArray();

        // Official Test Vectors
        private static readonly string V6_EAX_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14\n" +
            "KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq\n" +
            "pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1\n" +
            "QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=\n" +
            "-----END PGP MESSAGE-----\n";
        private static readonly string V6_OCB_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl\n" +
            "ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM\n" +
            "WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0\n" +
            "K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==\n" +
            "-----END PGP MESSAGE-----\n";
        private static readonly string V6_GCM_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa\n" +
            "v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax\n" +
            "Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS\n" +
            "+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==\n" +
            "-----END PGP MESSAGE-----\n";
        // Homemade test vectors from BC 1.72 to ensure backwards compat with pre-patch BC
        private static readonly string V5_EAX_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Generated using BC 1.72\n" +
            "\n" +
            "jB4EBwMIoM1rJmpJ+PVglCacbCVQOmFcJcAt84821mfUSQEHAQDGp5sLS9Ttznvd\n" +
            "gWNKeAVoVfZWtk/HxGkAgKnJBViUbWBhYW0mXA8Mwf29Maz34nnaixFTc5PC/O56\n" +
            "6fW7DLzJ9J09nkE=\n" +
            "=vApM\n" +
            "-----END PGP MESSAGE-----";
        private static readonly string V5_OCB_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Generated using BC 1.72\n" +
            "\n" +
            "jB4EBwMIZRVl03fl3ABgzCip0L+8pQMZ2AjYcmuAHbnUSAEHAgDCFxZXdafRqogj\n" +
            "PoUaOyuF3JsQs62nBTeEMaFY0TP8yLLMtina9q7V1OcFgvLvtSugd5PSY2ipAgwT\n" +
            "NCh2fmu6AA9Q6A==\n" +
            "=iJEV\n" +
            "-----END PGP MESSAGE-----";
        private static readonly string V5_GCM_PACKET_SEQUENCE = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Generated using BC 1.72\n" +
            "\n" +
            "jB4EBwMIoEl85k52SodgLetOxLRv2QjBLfVzPa9zhErURQEHAwA/UJOYkH5rHr1Z\n" +
            "BWN8oNhV/mcw45J+1+IfabaDFVlUVjVnBIIKCUYY+BEprJ8r/rtYCiVgw9+QJVfe\n" +
            "eI3EuSfMqQ==\n" +
            "=bgWx\n" +
            "-----END PGP MESSAGE-----";

        [Test]
        public void PaddingKnownBytes()
        {
            byte[] known = Strings.ToByteArray("thisIsKnownPadding");
            PaddingPacket packet = new PaddingPacket(known);
            Assert.That(Arrays.AreEqual(known, packet.GetPadding()));
        }

        [Test]
        public void PaddingRandom50Bytes()
        {
            SecureRandom random = new SecureRandom();
            PaddingPacket packet = new PaddingPacket(50, random);
            Assert.AreEqual(50, packet.GetPadding().Length);
        }

        [Test]
        public void PaddingPacketEncoding()
        {
            SecureRandom random = new SecureRandom();
            PaddingPacket packet = new PaddingPacket(32, random);

            MemoryStream bOut = new MemoryStream();
            using (BcpgOutputStream bcOut = new BcpgOutputStream(bOut))
            {
                packet.Encode(bcOut);
            }

            using (MemoryStream bIn = new MemoryStream(bOut.ToArray(), writable: false))
            {
                PgpObjectFactory factory = new PgpObjectFactory(bIn);
                PgpPadding padding = (PgpPadding)factory.NextPgpObject();
                Assert.That(Arrays.AreEqual(packet.GetPadding(), padding.GetPadding()));
            }
        }

        [Test, Explicit] // Incomplete implementation
        public void KnownV5TestVectorDecryptionTests()
        {
            // test known-good V5 test vectors
            ImplTestDecryption(V5_EAX_PACKET_SEQUENCE, Password, PlainText);
            ImplTestDecryption(V5_OCB_PACKET_SEQUENCE, Password, PlainText);
            ImplTestDecryption(V5_GCM_PACKET_SEQUENCE, Password, PlainText);
        }

        [Test, Explicit] // Incomplete implementation
        public void KnownV6TestVectorDecryptionTests()
        {
            // Test known-good V6 test vectors
            ImplTestDecryption(V6_EAX_PACKET_SEQUENCE, Password, PlainText);
            ImplTestDecryption(V6_OCB_PACKET_SEQUENCE, Password, PlainText);
            ImplTestDecryption(V6_GCM_PACKET_SEQUENCE, Password, PlainText);
        }

        [Test, Explicit] // Incomplete implementation
        public void PreferredAeadAlgorithmsImplicitlySupportAes128Ocb()
        {
            throw new NotImplementedException();

            //PreferredAEADCiphersuites.Combination implicit = new PreferredAEADCiphersuites.Combination(
            //    SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB);

            //PreferredAEADCiphersuites preferences = new PreferredAEADCiphersuites(false,
            //    new PreferredAEADCiphersuites.Combination[0]);

            //Assert.True(preferences.IsSupported(implicit));
            //Assert.That(Arrays.AreEqual(new PreferredAEADCiphersuites.Combination[0], preferences.getRawAlgorithms()));
            //Assert.That(Arrays.AreEqual(new PreferredAEADCiphersuites.Combination[]{implicit}, preferences.getAlgorithms()));
        }

        [Test, Explicit] // Incomplete implementation
        public void PreferredAeadAlgorithmsInvalidConstructor()
        {
            throw new NotImplementedException();

            //// odd number of data bytes
            //try
            //{
            //    new PreferredAeadCiphersuites(false, false, new byte[]{ 0x09, 0x02, 0x09 });
            //    Assert.Fail("Odd number of data bytes must throw.");
            //}
            //catch (ArgumentException)
            //{
            //    // expected
            //}
        }

        [Test, Explicit] // Incomplete implementation
        public void PreferredAeadAlgorithmsRoundtrip()
        {
            throw new NotImplementedException();

            //PreferredAEADCiphersuites preferences = new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]
            //    {
            //        new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
            //        new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.GCM),
            //        new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.CAMELLIA_256, AEADAlgorithmTags.OCB)
            //    });
            //isTrue(Arrays.areEqual(new byte[] { 0x09, 0x02, 0x09, 0x03, 0x0d, 0x02 }, preferences.getData()));

            //ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            //BCPGOutputStream bcpgOut = new BCPGOutputStream(bOut);

            //preferences.encode(bcpgOut);

            //ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            //SignatureSubpacketInputStream subpacketIn = new SignatureSubpacketInputStream(bIn);
            //SignatureSubpacket subpacket = subpacketIn.readPacket();
            //assert subpacket != null;
            //assert subpacket instanceof PreferredAEADCiphersuites;

            //PreferredAEADCiphersuites parsed = (PreferredAEADCiphersuites)subpacket;
            //Assert.That(Arrays.AreEqual(preferences.getRawAlgorithms(), parsed.getRawAlgorithms()));
        }

        [Test, Explicit] // Incomplete implementation
        public void RoundTripEncryptionDecryptionTests()
        {
            AeadAlgorithmTag[] aeadAlgs = new AeadAlgorithmTag[]{
                AeadAlgorithmTag.Eax,
                AeadAlgorithmTag.Ocb,
                AeadAlgorithmTag.Gcm,
            };
            SymmetricKeyAlgorithmTag[] symAlgs = new SymmetricKeyAlgorithmTag[]{
                SymmetricKeyAlgorithmTag.Aes128,
                SymmetricKeyAlgorithmTag.Aes192,
                SymmetricKeyAlgorithmTag.Aes256,
                SymmetricKeyAlgorithmTag.Camellia128,
                SymmetricKeyAlgorithmTag.Camellia192,
                SymmetricKeyAlgorithmTag.Camellia256,
            };

            // Test round-trip encryption
            foreach (var aeadAlg in aeadAlgs)
            {
                foreach (var symAlg in symAlgs)
                {
                    // OpenPGP v5
                    ImplTestRoundTrip(true, aeadAlg, symAlg, PlainText, Password);

                    // OpenPGP v6
                    ImplTestRoundTrip(false, aeadAlg, symAlg, PlainText, Password);
                }
            }
        }

        private void ImplTestDecryption(string armoredMessage, char[] password, byte[] expectedPlaintext)
        {
            MemoryStream messageIn = new MemoryStream(Strings.ToByteArray(armoredMessage), writable: false);
            ArmoredInputStream armorIn = new ArmoredInputStream(messageIn);
            PgpObjectFactory outerFactory = new PgpObjectFactory(armorIn);
            PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)outerFactory.NextPgpObject();

            for (int i = 0; i < encryptedDataList.Count; i++)
            {
                if (encryptedDataList[i] is PgpPbeEncryptedData symEncData)
                {
                    Stream decryptedIn = symEncData.GetDataStream(password);
                    PgpObjectFactory innerFactory = new PgpObjectFactory(decryptedIn);
                    PgpLiteralData literalData = (PgpLiteralData)innerFactory.NextPgpObject();

                    MemoryStream plaintextOut = new MemoryStream();
                    Streams.PipeAll(literalData.GetDataStream(), plaintextOut);
                    Assert.That(Arrays.AreEqual(expectedPlaintext, plaintextOut.ToArray()));

                    PgpObject o = innerFactory.NextPgpObject();
                    if (o is PgpPadding)
                    {
                        o = innerFactory.NextPgpObject();
                    }

                    Assert.IsNull(o, "Unexpected trailing packet.");
                }
            }
        }

        private string ImplTestEncryption(bool v5AEAD, AeadAlgorithmTag aeadAlg, SymmetricKeyAlgorithmTag symAlg,
            byte[] plaintext, char[] password)
        {
            throw new NotImplementedException();

            //MemoryStream ciphertextOut = new MemoryStream();
            //PGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
            //PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(symAlg);
            //if (v5AEAD)
            //{
            //    encBuilder.setUseV5AEAD();
            //}
            //else
            //{
            //    encBuilder.setUseV6AEAD();
            //}
            //encBuilder.setWithAEAD(aeadAlg, 6);

            //PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder, false);
            //encGen.setForceSessionKey(true);
            //PBEKeyEncryptionMethodGenerator encMethodGen = new BcPBEKeyEncryptionMethodGenerator(password,
            //    digestCalculatorProvider.get(HashAlgorithmTags.SHA256));
            //encGen.addMethod(encMethodGen);
            //OutputStream encOut = encGen.open(ciphertextOut, new byte[1 << 9]);
            //encOut.flush();
            //PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            //OutputStream litOut = litGen.open(encOut, PGPLiteralData.UTF8, "", new Date(), new byte[1 << 9]);

            //litOut.write(plaintext);
            //litOut.flush();
            //litOut.close();

            //encOut.flush();
            //encOut.close();

            //ByteArrayOutputStream armoredMsg = new ByteArrayOutputStream();
            //ArmoredOutputStream armorOut = new ArmoredOutputStream(armoredMsg);
            //armorOut.write(ciphertextOut.toByteArray());
            //armorOut.flush();
            //armorOut.close();

            //PrintHex(ciphertextOut.toByteArray());

            //return armoredMsg.toString();
        }

        private void ImplTestRoundTrip(bool v5AEAD, AeadAlgorithmTag aeadAlg, SymmetricKeyAlgorithmTag symAlg,
            byte[] plaintext, char[] password)
        {
            string armored = ImplTestEncryption(v5AEAD, aeadAlg, symAlg, plaintext, password);
            ImplTestDecryption(armored, password, plaintext);
        }
    }
}
