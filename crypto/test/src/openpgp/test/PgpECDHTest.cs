using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
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

        private static readonly byte[] curve25519Message = Base64.Decode(
            "hE4Dg5N9lpwvavoSAQdApL1xhvz/28almLuqHjyrzwVRnB+37yODIRZCkfPk"
          + "GEIgd9uff5j8mYbI9ErePgRI47fDnQPu8mI4hTOhe8pHzyXSTwFf5CesSdME"
          + "Td9g+UG6cYt/i+cHQWMQD7a53fMNFxPGVYLUFXC5cQh+KvBPghfdoFQMhbR+"
          + "GDgauMrgtk//Os0WCYWJa7VZkD5ak3sbMwk=");

        //private static readonly byte[] curve25519Pub =    Base64.Decode(
        //    "mDMEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
        //    "jfgnnG60N1Rlc3QgS2V5IChEbyBub3QgdXNlIGZvciByZWFsLikgPHRlc3RAd29v" +
        //    "ZHMtZ2VibGVyLmNvbT6IlgQTFggAPhYhBIuq+f4gKmIa9ZKEqJdUhr00IJstBQJc" +
        //    "TPJ2AhsDBQkB4TOABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJdUhr00IJst" +
        //    "dHAA/RDOjus5OZL2m9Q9dxOVnWNguT7Cr5cWdJxUeKAWE2c6AQCcQZWA4SmV1dkJ" +
        //    "U0XKmLeu3xWDpqrydT4+vQXb/Qm9B7g4BFxM8nYSCisGAQQBl1UBBQEBB0AY3XTS" +
        //    "6S1pwFNc1QhNpEKTStG+LAJpiHPK9QyXBbW9dQMBCAeIfgQYFggAJhYhBIuq+f4g" +
        //    "KmIa9ZKEqJdUhr00IJstBQJcTPJ2AhsMBQkB4TOAAAoJEJdUhr00IJstmAsBAMRJ" +
        //    "pvh8iegwrJDMoQc53ZqDRsbieElV6ofB80a+jkzZAQCgpAaY4hZc8GUan2JIqkg0" +
        //    "gs23h4au7H79KqXYG4a+Bg==");

        private static readonly byte[] curve25519Priv = Base64.Decode(
        "lIYEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
            "jfgnnG7+BwMCgEr7OFDl3dTpT73rmw6vIwiTGqjx+Xbe8cq4l24q2AOtzO+UR97q" +
            "7ypL41jtt7BY7uoxhF+NCKzYEtRoqyaM0lfjDlOVRJP6SYRixK2UHLQ3VGVzdCBL" +
            "ZXkgKERvIG5vdCB1c2UgZm9yIHJlYWwuKSA8dGVzdEB3b29kcy1nZWJsZXIuY29t" +
            "PoiWBBMWCAA+FiEEi6r5/iAqYhr1koSol1SGvTQgmy0FAlxM8nYCGwMFCQHhM4AF" +
            "CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQl1SGvTQgmy10cAD9EM6O6zk5kvab" +
            "1D13E5WdY2C5PsKvlxZ0nFR4oBYTZzoBAJxBlYDhKZXV2QlTRcqYt67fFYOmqvJ1" +
            "Pj69Bdv9Cb0HnIsEXEzydhIKKwYBBAGXVQEFAQEHQBjddNLpLWnAU1zVCE2kQpNK" +
            "0b4sAmmIc8r1DJcFtb11AwEIB/4HAwItKjH+kGqkMelkEdIRxSLFeCsB/A64n+os" +
            "X9nWVYsrixEWT5JcRWBniI1PKt9Cm15Yt8KQSAFDJIj5tnEm28x5RM0CzFHQ9Ej2" +
            "8Q2Lt0RoiH4EGBYIACYWIQSLqvn+ICpiGvWShKiXVIa9NCCbLQUCXEzydgIbDAUJ" +
            "AeEzgAAKCRCXVIa9NCCbLZgLAQDESab4fInoMKyQzKEHOd2ag0bG4nhJVeqHwfNG" +
            "vo5M2QEAoKQGmOIWXPBlGp9iSKpINILNt4eGrux+/Sql2BuGvgY=");

        private static readonly char[] curve25519Pwd = "foobar".ToCharArray();

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

        private void TestCurve25519Message()
        {
            PgpSecretKeyRing ring = new PgpSecretKeyRing(curve25519Priv);

            PgpObjectFactory pgpF = new PgpObjectFactory(curve25519Message);

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            Stream clear = encP.GetDataStream(ring.GetSecretKey(encP.KeyId).ExtractPrivateKey(curve25519Pwd));

            pgpF = new PgpObjectFactory(clear);

            PgpCompressedData cd = (PgpCompressedData)pgpF.NextPgpObject();

            PgpLiteralData ld = (PgpLiteralData)new PgpObjectFactory(cd.GetDataStream()).NextPgpObject();

            clear = ld.GetInputStream();
            MemoryStream bOut = new MemoryStream();

            int ch;
            while ((ch = clear.ReadByte()) >= 0)
            {
                bOut.WriteByte((byte)ch);
            }

            byte[] output = bOut.ToArray();

            if (!AreEqual(output, Strings.ToByteArray("Hello world\n")))
            {
                Fail("wrong plain text in generated packet");
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

        private void EncryptDecryptTest()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            byte[] text = Encoding.ASCII.GetBytes("hello world!");

            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            keyGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));

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

            EncryptDecryptTest();

            TestCurve25519Message();

            Generate();
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

                        if (!certification.VerifyCertification(First(pubKeyRing.GetPublicKey().GetUserIds()), pubKeyRing.GetPublicKey()))
                        {
                            Fail("subkey certification does not verify");
                        }
                    }
                }
            }
        }

        private static T First<T>(IEnumerable<T> e)
        {
            var n = e.GetEnumerator();
            Assert.IsTrue(n.MoveNext());
            return n.Current;
        }

        public override string Name
        {
            get { return "PgpECDHTest"; }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
