using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpEdDsaTest
        : SimpleTest
    {
        private static readonly string edDSASampleKey =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: Alice's OpenPGP certificate\n" +
                "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
                "\n" +
                "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE\n" +
                "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy\n" +
                "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO\n" +
                "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4\n" +
                "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s\n" +
                "E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb\n" +
                "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn\n" +
                "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=\n" +
                "=iIGO\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        private static readonly string edDSASecretKey =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: Alice's OpenPGP Transferable Secret Key\n" +
                "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
                "\n" +
                "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
                "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
                "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
                "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
                "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
                "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
                "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
                "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
                "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
                "Pnn+We1aTBhaGa86AQ==\n" +
                "=n8OM\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        private static readonly string revBlock =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: Alice's revocation certificate\n" +
                "Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html\n" +
                "\n" +
                "iHgEIBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXaWkOwIdAAAKCRDyMVUM\n" +
                "T0fjjoBlAQDA9ukZFKRFGCooVcVoDVmxTaHLUXlIg9TPh2f7zzI9KgD/SLNXUOaH\n" +
                "O6TozOS7C9lwIHwwdHdAxgf5BzuhLT9iuAM=\n" +
                "=Tm8h\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        public override string Name
        {
            get { return "PgpEdDsaTest"; }
        }

        private void EncryptDecryptTest(PgpPublicKey pubKey, PgpPrivateKey secKey)
        {
            byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.UtcNow);

            pOut.Write(text, 0, text.Length);
            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, new SecureRandom());
            cPk.AddMethod(pubKey);

            Stream cOut = cPk.Open(new UncloseableStream(cbOut), data.Length);

            cOut.Write(data, 0, data.Length);
            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            Stream clear = encP.GetDataStream(secKey);

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
                Fail("wrong plain text in generated packet");
            }
        }

        private void KeyRingTest()
        {
            SecureRandom random = new SecureRandom();

            string identity = "eric@bouncycastle.org";
            char[] passPhrase = "Hello, world!".ToCharArray();

            Ed25519KeyPairGenerator edKp = new Ed25519KeyPairGenerator();
            edKp.Init(new Ed25519KeyGenerationParameters(random));

            PgpKeyPair dsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, edKp.GenerateKeyPair(), DateTime.UtcNow);

            X25519KeyPairGenerator dhKp = new X25519KeyPairGenerator();
            dhKp.Init(new X25519KeyGenerationParameters(random));

            PgpKeyPair dhKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, dhKp.GenerateKeyPair(), DateTime.UtcNow);

            EncryptDecryptTest(dhKeyPair.PublicKey, dhKeyPair.PrivateKey);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, dsaKeyPair,
                identity, SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, random);

            keyRingGen.AddSubKey(dhKeyPair);

            MemoryStream secretOut = new MemoryStream();

            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();

            secRing.Encode(secretOut);

            secretOut.Close();
            secRing = new PgpSecretKeyRing(secretOut.ToArray());

            var publicKeys = new List<PgpPublicKey>(secRing.GetPublicKeys());

            PgpPublicKey sKey = publicKeys[1];
            PgpPublicKey vKey = secRing.GetPublicKey();

            int count = 0;
            foreach (var sig in sKey.GetSignatures())
            {
                if (sig.KeyId == vKey.KeyId
                    && sig.SignatureType == PgpSignature.SubkeyBinding)
                {
                    count++;
                    sig.InitVerify(vKey);

                    if (!sig.VerifyCertification(vKey, sKey))
                    {
                        Fail("failed to verify sub-key signature.");
                    }
                }
            }

            IsTrue(count == 1);

            secRing = new PgpSecretKeyRing(secretOut.ToArray());
            PgpPublicKey pubKey = null;
            PgpPrivateKey privKey = null;

            foreach (var candidate in secRing.GetPublicKeys())
            {
                if (candidate.IsEncryptionKey)
                {
                    pubKey = candidate;
                    privKey = secRing.GetSecretKey(pubKey.KeyId).ExtractPrivateKey(passPhrase);
                    break;
                }
            }

            EncryptDecryptTest(pubKey, privKey);
        }

        public override void PerformTest()
        {
            ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(edDSASampleKey), false));

            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(aIn);

            IsTrue(AreEqual(Hex.Decode("EB85 BB5F A33A 75E1 5E94 4E63 F231 550C 4F47 E38E"),
                pubKeyRing.GetPublicKey().GetFingerprint()));

            aIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(edDSASecretKey), false));

            PgpSecretKeyRing secRing = new PgpSecretKeyRing(aIn);

            IsTrue(secRing.GetSecretKey().IsSigningKey);

            PgpSignatureGenerator pgpGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);

            pgpGen.InitSign(PgpSignature.SubkeyBinding, secRing.GetSecretKey().ExtractPrivateKey(null));

            PgpSignature sig = pgpGen.GenerateCertification(pubKeyRing.GetPublicKey(),
                pubKeyRing.GetPublicKey(5145070902336167606L));

            sig.InitVerify(pubKeyRing.GetPublicKey());

            IsTrue(sig.VerifyCertification(pubKeyRing.GetPublicKey(), pubKeyRing.GetPublicKey(5145070902336167606L)));

            EncryptDecryptTest(pubKeyRing.GetPublicKey(5145070902336167606L),
                secRing.GetSecretKey(5145070902336167606L).ExtractPrivateKey(null));

            aIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(revBlock), false));

            PgpSignatureList sigs = (PgpSignatureList)new PgpObjectFactory(aIn).NextPgpObject();

            sig = sigs[0];

            sig.InitVerify(pubKeyRing.GetPublicKey());

            IsTrue(sig.VerifyCertification(pubKeyRing.GetPublicKey()));

            KeyRingTest();
            SksKeyTest();
            AliceKeyTest();
        }

        private void AliceKeyTest()
        {
            byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};
            ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(edDSASampleKey), false));

            PgpPublicKeyRing rng = new PgpPublicKeyRing(aIn);

            aIn = new ArmoredInputStream(new MemoryStream(Strings.ToByteArray(edDSASecretKey), false));

            PgpSecretKeyRing secRing = new PgpSecretKeyRing(aIn);

            PgpPublicKey pubKey = rng.GetPublicKey(5145070902336167606L);
            PgpPrivateKey privKey = secRing.GetSecretKey(5145070902336167606L).ExtractPrivateKey(null);
        
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            MemoryStream ldOut = new MemoryStream();
            Stream pOut = lData.Open(ldOut, PgpLiteralDataGenerator.Utf8, PgpLiteralData.Console, text.Length, DateTime.UtcNow);

            pOut.Write(text, 0, text.Length);
            pOut.Close();

            byte[] data = ldOut.ToArray();

            MemoryStream cbOut = new MemoryStream();

            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true);

            cPk.AddMethod(pubKey);

            Stream cOut = cPk.Open(new UncloseableStream(cbOut), data.Length);

            cOut.Write(data, 0, data.Length);
            cOut.Close();

            PgpObjectFactory pgpF = new PgpObjectFactory(cbOut.ToArray());

            PgpEncryptedDataList encList = (PgpEncryptedDataList)pgpF.NextPgpObject();

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];

            Stream clear = encP.GetDataStream(privKey);

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
                Fail("wrong plain text in generated packet");
            }
        }

        private void SksKeyTest()
        {
            byte[] data = Strings.ToByteArray("testing, 1, 2, 3, testing...");

            ArmoredInputStream aIn = new ArmoredInputStream(GetTestDataAsStream("openpgp.eddsa-sks-pub-keyring.asc"));

            // make sure we can parse it without falling over.
            PgpPublicKeyRing rng = new PgpPublicKeyRing(aIn);

            PgpEncryptedDataGenerator encDataGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true);

            encDataGen.AddMethod(rng.GetPublicKey(6752245936421807937L));

            MemoryStream cbOut = new MemoryStream();

            Stream cOut = encDataGen.Open(new UncloseableStream(cbOut), data.Length);
            cOut.Write(data, 0, data.Length);
            cOut.Close();
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
