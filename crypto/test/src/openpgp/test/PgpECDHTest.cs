using System;
using System.Collections;
using System.IO;
using System.Text;

using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpECDHTest
        : SimpleTest
    {
        private static readonly byte[] testPubKey =
            Base64.Decode(
                "mFIEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
                "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKstFBUZXN0IEVDRFNB" +
                "LUVDREggKEtleSBhbmQgc3Via2V5IGFyZSAyNTYgYml0cyBsb25nKSA8dGVzdC5l" +
                "Y2RzYS5lY2RoQGV4YW1wbGUuY29tPoh6BBMTCAAiBQJRvgbAAhsDBgsJCAcDAgYV" +
                "CAIJCgsEFgIDAQIeAQIXgAAKCRD3wDlWjFo9U5O2AQDi89NO6JbaIObC63jMMWsi" +
                "AaQHrBCPkDZLibgNv73DLgD/faouH4YZJs+cONQBPVnP1baG1NpWR5ppN3JULFcr" +
                "hcq4VgRRvgbAEggqhkjOPQMBBwIDBLtY8Nmfz0zSEa8C1snTOWN+VcT8pXPwgJRy" +
                "z6kSP4nPt1xj1lPKj5zwPXKWxMkPO9ocqhKdg2mOh6/rc1ObIoMDAQgHiGEEGBMI" +
                "AAkFAlG+BsACGwwACgkQ98A5VoxaPVN8cgEAj4dMNMNwRSg2ZBWunqUAHqIedVbS" +
                "dmwmbysD192L3z4A/ReXEa0gtv8OFWjuALD1ovEK8TpDORLUb6IuUb5jUIzY");

        private static readonly byte[] testPrivKey =
            Base64.Decode(
                "lKUEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
                "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKs/gcDAo11YYCae/K2" +
                "1uKGJ/uU4b4QHYnPIsAdYpuo5HIdoAOL/WwduRa8C6vSFrtMJLDqPK3BUpMz3CXN" +
                "GyMhjuaHKP5MPbBZkIfgUGZO5qvU9+i0UFRlc3QgRUNEU0EtRUNESCAoS2V5IGFu" +
                "ZCBzdWJrZXkgYXJlIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhLmVjZGhAZXhh" +
                "bXBsZS5jb20+iHoEExMIACIFAlG+BsACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B" +
                "AheAAAoJEPfAOVaMWj1Tk7YBAOLz007oltog5sLreMwxayIBpAesEI+QNkuJuA2/" +
                "vcMuAP99qi4fhhkmz5w41AE9Wc/VtobU2lZHmmk3clQsVyuFyg==");

        private static readonly byte[] testMessage =
            Base64.Decode(
                "hH4Dp5+FdoujIBwSAgMErx4BSvgXY3irwthgxU8zPoAoR+8rhmxdpwbw6ZJAO2GX" +
                "azWJ85JNcobHKDeGeUq6wkTFu+g6yG99gIX8J5xJAjBRhyCRcaFgwbdDV4orWTe3" +
                "iewiT8qs4BQ23e0c8t+thdKoK4thMsCJy7wSKqY0sJTSVAELroNbCOi2lcO15YmW" +
                "6HiuFH7VKWcxPUBjXwf5+Z3uOKEp28tBgNyDrdbr1BbqlgYzIKq/pe9zUbUXfitn" +
                "vFc6HcGhvmRQreQ+Yw1x3x0HJeoPwg==");

        private static readonly byte[] testX25519PubKey =
            Base64.Decode(
                "mDMEX9XwXhYJKwYBBAHaRw8BAQdAR5ZghmMHL8wldNlOkmbaiAOdyF5V5bgZdKq7" +
                "L+yb4A20HEVDREggPHRlc3QuZWNkaEBleGFtcGxlLmNvbT6IkAQTFggAOBYhBGoy" +
                "UrxNv7c3S2JjGzewWiN8tfzXBQJf1fBeAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4B" +
                "AheAAAoJEDewWiN8tfzX0ZMA/AhEvrIgu+29eMQeuHOwX1ZY/UssU5TdVROQzGTL" +
                "n5cgAP9hIKtt/mZ112HiAHDuWk2JskdtsuopnrEccz4PSEkSDLg4BF/V8F4SCisG" +
                "AQQBl1UBBQEBB0DLPhNt/6GHDbb7vZW/iMsbXTZpgJNQiT6QA/4EzgYQLwMBCAeI" +
                "eAQYFggAIBYhBGoyUrxNv7c3S2JjGzewWiN8tfzXBQJf1fBeAhsMAAoJEDewWiN8" +
                "tfzXU34BAKJJLDee+qJCmUI20sMy/YoKfWmMnH2RBBHmLV8FAJ7vAP0e2wGixEfs" +
                "oPqe8fHmvjQGxSByOyQGn7yD+oq9nVzTAA==");

        private static readonly byte[] testX25519PrivKey =
            Base64.Decode(
                "lIYEX9XwXhYJKwYBBAHaRw8BAQdAR5ZghmMHL8wldNlOkmbaiAOdyF5V5bgZdKq7" +
                "L+yb4A3+BwMCMscozrXr93fOFmtxu/BJjEJrwRl20Jrv9lryfM+SF4UHgVMmJUpJ" +
                "1RuTbSnM2KaqHwOgmdrvf2FJnpg1vMafBk1CmopqkRzzrbJ6xQhiPrQcRUNESCA8" +
                "dGVzdC5lY2RoQGV4YW1wbGUuY29tPoiQBBMWCAA4FiEEajJSvE2/tzdLYmMbN7Ba" +
                "I3y1/NcFAl/V8F4CGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQN7BaI3y1" +
                "/NfRkwD8CES+siC77b14xB64c7BfVlj9SyxTlN1VE5DMZMuflyAA/2Egq23+ZnXX" +
                "YeIAcO5aTYmyR22y6imesRxzPg9ISRIMnIsEX9XwXhIKKwYBBAGXVQEFAQEHQMs+" +
                "E23/oYcNtvu9lb+IyxtdNmmAk1CJPpAD/gTOBhAvAwEIB/4HAwJ7ShSBrUuUAM5r" +
                "G4I/gJKo+eBmbNC4NM81eALAF1vcovZPsGsiZ8IgXT64XiC1bpeAoINn6vM4vVbi" +
                "LqNKqu6ll3ZgQ4po6vCW9GkhuEMmiHgEGBYIACAWIQRqMlK8Tb+3N0tiYxs3sFoj" +
                "fLX81wUCX9XwXgIbDAAKCRA3sFojfLX811N+AQCiSSw3nvqiQplCNtLDMv2KCn1p" +
                "jJx9kQQR5i1fBQCe7wD9HtsBosRH7KD6nvHx5r40BsUgcjskBp+8g/qKvZ1c0wA=");

        private static readonly byte[] testX25519Message =
            Base64.Decode(
                "hF4DbDc2fNL0VcUSAQdAqdV0v1D4X9cuGrT7+oQBpMFnw1wdfAcxH9xdO00s2HUw" +
                "qB+XkIRETH7yesynLOKajmYftMWZRyTnW2tJUc1w5NFPjPxcbvd2bYmqkY57uAFg" +
                "0kcBKhFklH2LRbBNThtQr3jn2YEFbNnhiGfOpoHfCn0oFh5RbXDwm+P3Q3tksvpZ" +
                "wEGe2VkxLLe7BWnv/sRINQ2YpuaYshe8hw==");

        private void Generate()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            //
            // Generate a master key
            //
            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            keyGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));

            AsymmetricCipherKeyPair kpSign = keyGen.GenerateKeyPair();

            PgpKeyPair ecdsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDsa, kpSign, DateTime.UtcNow);

            //
            // Generate an encryption key
            //
            keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            keyGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));

            AsymmetricCipherKeyPair kpEnc = keyGen.GenerateKeyPair();

            PgpKeyPair ecdhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpEnc, DateTime.UtcNow);

            //
            // Generate a key ring
            //
            char[] passPhrase = "test".ToCharArray();
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, ecdsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, random);
            keyRingGen.AddSubKey(ecdhKeyPair);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            // TODO: add check of KdfParameters
            DoBasicKeyRingCheck(pubRing);

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            if (!Arrays.AreEqual(pubRing.GetEncoded(), pubRingEnc.GetEncoded()))
            {
                Fail("public key ring encoding failed");
            }

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            if (!Arrays.AreEqual(secRing.GetEncoded(), secRingEnc.GetEncoded()))
            {
                Fail("secret key ring encoding failed");
            }

            PgpPrivateKey pgpPrivKey = secRing.GetSecretKey().ExtractPrivateKey(passPhrase);
        }

        private void Generate25519()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            //
            // Generate a master key
            //
            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("Ed25519");
            keyGen.Init(new ECKeyGenerationParameters(GnuObjectIdentifiers.Ed25519, random));

            AsymmetricCipherKeyPair kpSign = keyGen.GenerateKeyPair();

            PgpKeyPair ecdsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, kpSign, DateTime.UtcNow);

            //
            // Generate an encryption key
            //
            keyGen = GeneratorUtilities.GetKeyPairGenerator("X25519");
            keyGen.Init(new ECKeyGenerationParameters(MiscObjectIdentifiers.Curve25519, random));

            AsymmetricCipherKeyPair kpEnc = keyGen.GenerateKeyPair();

            PgpKeyPair ecdhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpEnc, DateTime.UtcNow);

            //
            // Generate a key ring
            //
            char[] passPhrase = "test".ToCharArray();
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, ecdsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, random);
            keyRingGen.AddSubKey(ecdhKeyPair);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            // TODO: add check of KdfParameters
            DoBasicKeyRingCheck(pubRing);

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            if (!Arrays.AreEqual(pubRing.GetEncoded(), pubRingEnc.GetEncoded()))
            {
                Fail("public key ring encoding failed");
            }

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            if (!Arrays.AreEqual(secRing.GetEncoded(), secRingEnc.GetEncoded()))
            {
                Fail("secret key ring encoding failed");
            }

            // Extract back the ECDH key and verify the encoded values to ensure correct endianness
            PgpSecretKey pgpSecretKey = secRing.GetSecretKey(ecdhKeyPair.KeyId);
            PgpPrivateKey pgpPrivKey = pgpSecretKey.ExtractPrivateKey(passPhrase);

            if (!Arrays.AreEqual(((X25519PrivateKeyParameters)kpEnc.Private).GetEncoded(), ((X25519PrivateKeyParameters)pgpPrivKey.Key).GetEncoded()))
            {
                Fail("private key round trip failed");
            }
            if (!Arrays.AreEqual(((X25519PublicKeyParameters)kpEnc.Public).GetEncoded(), ((X25519PublicKeyParameters)pgpSecretKey.PublicKey.GetKey()).GetEncoded()))
            {
                Fail("private key round trip failed");
            }
        }

        private void TestDecrypt(PgpSecretKeyRing secretKeyRing)
        {
            PgpObjectFactory pgpF = new PgpObjectFactory(testMessage);

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            PgpSecretKey secretKey = secretKeyRing.GetSecretKey(); // secretKeyRing.GetSecretKey(encP.KeyId);

    //        PgpPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyEncryptorBuilder());

    //        clear = encP.getDataStream(pgpPrivKey, "BC");
    //
    //        bOut.reset();
    //
    //        while ((ch = clear.read()) >= 0)
    //        {
    //            bOut.write(ch);
    //        }
    //
    //        out = bOut.toByteArray();
    //
    //        if (!AreEqual(out, text))
    //        {
    //            fail("wrong plain text in Generated packet");
    //        }
        }

        private void EncryptDecryptTest(string algorithm, DerObjectIdentifier curve)
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            byte[] text = Encoding.ASCII.GetBytes("hello world!");

            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            keyGen.Init(new ECKeyGenerationParameters(curve, random));

            AsymmetricCipherKeyPair kpEnc = keyGen.GenerateKeyPair();

            PgpKeyPair ecdhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpEnc, DateTime.UtcNow);

            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.UtcNow);

            pOut.Write(text, 0, text.Length);

            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, random);
            cPk.AddMethod(ecdhKeyPair.PublicKey);

            Stream cOut = cPk.Open(new UncloseableStream(cbOut), data.Length);

            cOut.Write(data, 0, data.Length);

            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            Stream clear = encP.GetDataStream(ecdhKeyPair.PrivateKey);

            pgpF = new PgpObjectFactory(clear);

            PgpLiteralData ld = (PgpLiteralData)pgpF.NextPgpObject();

            clear = ld.GetInputStream();
            MemoryStream bOut = new MemoryStream();

            int ch;
            while ((ch = clear.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
            }

            byte[] output = bOut.ToArray();

            if (!AreEqual(output, text))
            {
                Fail("wrong plain text in Generated packet");
            }
        }


        private void EncryptDecryptX25519KeysTest()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            /*IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            keyGen.Init(new ECKeyGenerationParameters(curve, random));

            AsymmetricCipherKeyPair kpEnc = keyGen.GenerateKeyPair();

            PgpKeyPair ecdhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, kpEnc, DateTime.UtcNow);*/
            PgpPublicKeyRing publicKeyRing = new PgpPublicKeyRing(testX25519PubKey);

            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testX25519PrivKey);

            PgpSecretKey secretKey = secretKeyRing.GetSecretKey(0x6c37367cd2f455c5);

            byte[] text = Encoding.ASCII.GetBytes("hello world!");

            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.UtcNow);

            pOut.Write(text, 0, text.Length);

            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, random);
            cPk.AddMethod(publicKeyRing.GetPublicKey(0x6c37367cd2f455c5));

            Stream cOut = cPk.Open(new UncloseableStream(cbOut), data.Length);

            cOut.Write(data, 0, data.Length);

            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            Stream clear = encP.GetDataStream(secretKey.ExtractPrivateKey("test".ToCharArray()));

            pgpF = new PgpObjectFactory(clear);

            PgpLiteralData ld = (PgpLiteralData)pgpF.NextPgpObject();

            clear = ld.GetInputStream();
            MemoryStream bOut = new MemoryStream();

            int ch;
            while ((ch = clear.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
            }

            byte[] output = bOut.ToArray();

            if (!AreEqual(output, text))
            {
                Fail("wrong plain text in Generated packet");
            }
        }

        private void GnuPGCrossCheck()
        {
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testX25519PrivKey);

            PgpObjectFactory pgpF = new PgpObjectFactory(testX25519Message);

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            PgpSecretKey secretKey = secretKeyRing.GetSecretKey(0x6c37367cd2f455c5);

            PgpPrivateKey pgpPrivKey = secretKey.ExtractPrivateKey("test".ToCharArray());

            Stream clear = encP.GetDataStream(pgpPrivKey);

            pgpF = new PgpObjectFactory(clear);

            PgpCompressedData c1 = (PgpCompressedData)pgpF.NextPgpObject();

            pgpF = new PgpObjectFactory(c1.GetDataStream());

            PgpLiteralData ld = (PgpLiteralData)pgpF.NextPgpObject();

            Stream inLd = ld.GetDataStream();
            byte[] bytes = Streams.ReadAll(inLd);

            if (!Arrays.AreEqual(bytes, Encoding.ASCII.GetBytes("hello world!")))
            {
                Fail("wrong plain text in decrypted packet");
            }
        }

        public override void PerformTest()
        {
            //
            // Read the public key
            //
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(testPubKey);

            DoBasicKeyRingCheck(pubKeyRing);

            //
            // Read the private key
            //
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testPrivKey);

            TestDecrypt(secretKeyRing);

            EncryptDecryptTest("ECDH", SecObjectIdentifiers.SecP256r1);

            EncryptDecryptTest("X25519", MiscObjectIdentifiers.Curve25519);

            GnuPGCrossCheck();

            Generate();

            Generate25519();

            EncryptDecryptX25519KeysTest();
        }

        private void DoBasicKeyRingCheck(PgpPublicKeyRing pubKeyRing)
        {
            foreach (PgpPublicKey pubKey in pubKeyRing.GetPublicKeys())
            {
                if (pubKey.IsMasterKey)
                {
                    if (pubKey.IsEncryptionKey)
                    {
                        Fail("master key showed as encryption key!");
                    }
                }
                else
                {
                    if (!pubKey.IsEncryptionKey)
                    {
                        Fail("sub key not encryption key!");
                    }

                    foreach (PgpSignature certification in pubKeyRing.GetPublicKey().GetSignatures())
                    {
                        certification.InitVerify(pubKeyRing.GetPublicKey());

                        if (!certification.VerifyCertification((string)First(pubKeyRing.GetPublicKey().GetUserIds()), pubKeyRing.GetPublicKey()))
                        {
                            Fail("subkey certification does not verify");
                        }
                    }
                }
            }
        }

        private static object First(IEnumerable e)
        {
            IEnumerator n = e.GetEnumerator();
            Assert.IsTrue(n.MoveNext());
            return n.Current;
        }

        public override string Name
        {
            get { return "PgpECDHTest"; }
        }

        public static void Main(string[] args)
        {
            RunTest(new PgpECDHTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
