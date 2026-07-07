using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class Argon2S2kTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly string TestMsgPassword = "password";

        // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-
        private static readonly string TestMsgAes128 = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Encrypted using AES with 128-bit key\n" +
            "Comment: Session key: 01FE16BBACFD1E7B78EF3B865187374F\n" +
            "\n" +
            "wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+\n" +
            "YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH\n" +
            "XfA3pqV4mTzF\n" +
            "=uIks\n" +
            "-----END PGP MESSAGE-----";

        // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-a
        private static readonly string TestMsgAes192 = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Encrypted using AES with 192-bit key\n" +
            "Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955AF8DFE194\n" +
            "\n" +
            "wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw\n" +
            "F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys\n" +
            "LVg77Mwwfgl2n/d572WciAM=\n" +
            "=n8Ma\n" +
            "-----END PGP MESSAGE-----";

        // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-ae
        private static readonly string TestMsgAes256 = "-----BEGIN PGP MESSAGE-----\n" +
            "Comment: Encrypted using AES with 256-bit key\n" +
            "Comment: Session key: BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEF...\n" +
            "Comment: Session key: ...C13BAB2F1F8E18FB74580D8B0\n" +
            "\n" +
            "wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu\n" +
            "623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K\n" +
            "95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==\n" +
            "-----END PGP MESSAGE-----";

        private static readonly string TestMsgPlain = "Hello, world!";

        ///**
        // * RFC 9106 sec. 3.1 requires the Argon2 memory size m to satisfy m &ge; 8*p,
        // * i.e. memorySizeExponent &ge; 3 + ceil(log2(p)) = 3 + bitLen(p - 1). The
        // * key-derivation bounds check in PGPUtil.makeKeyFromPassPhrase now enforces
        // * that floor (previously it only rejected memorySizeExponent &lt; 3).
        // * <p>
        // * The {@link S2K.Argon2Params} constructor blocks building a sub-floor
        // * specifier, so a v6 SKESK wire form with parallelism = 4 and
        // * memorySizeExponent = 4 (m = 16 KiB &lt; 8*p = 32 KiB) is crafted and
        // * parsed - the packet parser does not validate the floor - and the derived
        // * S2K is fed to the key-derivation path, which must reject it.
        // */
        //[Test]
        //public void CheckArgon2MinMemoryExpFloor()
        //{
        //    byte[] body = V6SkeskBodyWithArgon2(1, 4, 4);
        //    S2k s2k = new SymmetricKeyEncSessionPacket(new BcpgInputStream(new MemoryStream(body))).S2k;

        //    try
        //    {
        //        PgpUtilities.MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes256, s2k, TestMsgPassword.ToCharArray());
        //        Assert.Fail("memorySizeExponent below 3 + bitLen(parallelism - 1) should be rejected");
        //    }
        //    catch (PgpException e)
        //    {
        //        Assert.AreEqual("memory size exponent out of range", e.Message);
        //    }
        //}

        ///**
        // * Build the body of a v6 {@link SymmetricKeyEncSessionPacket} (the octets
        // * after the packet frame) carrying an Argon2 S2K with the given parameters.
        // * The surrounding SKESK fields are spec-shaped but arbitrary - only the
        // * parsed S2K is used.
        // *
        // * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc">
        // *     RFC 9580 sec. 5.3 - Symmetric-Key Encrypted Session Key Packet</a>
        // */
        //private static byte[] V6SkeskBodyWithArgon2(int passes, int parallelism, int memSizeExp)
        //{
        //    // OCB tag is 16 octets per RFC 9580 sec. 5.13.2.
        //    int ivLen = 15;
        //    int sessionKeyLen = 16;
        //    int authTagLen = 16;
        //    int s2kOctets = 1 + 16 + 3;
        //    int next5FieldsCount = 1 /* encAlgo */ + 1 /* aeadAlgo */ + 1 /* s2kCount */ + s2kOctets + ivLen;

        //    byte[] body = new byte[1 /* version */ + 1 /* count */ + next5FieldsCount + sessionKeyLen + authTagLen];
        //    int p = 0;
        //    body[p++] = (byte)SymmetricKeyEncSessionPacket.Version6;
        //    body[p++] = (byte)next5FieldsCount;
        //    body[p++] = (byte)SymmetricKeyAlgorithmTag.Aes256;
        //    body[p++] = (byte)AeadAlgorithmTag.Ocb;
        //    body[p++] = (byte)s2kOctets;

        //    // Argon2 S2K wire form
        //    body[p++] = (byte)S2k.Argon2;
        //    p += 16; // 16-octet salt - content irrelevant for the floor check
        //    body[p++] = (byte)passes;
        //    body[p++] = (byte)parallelism;
        //    body[p++] = (byte)memSizeExp;

        //    // IV + session key + auth tag stay zero; the floor check fires during
        //    // key derivation, before any of that is consulted.
        //    return body;
        //}

        [Test]
        public void Encoding()
        {
            byte[] salt = SecureRandom.GetNextBytes(Random, 16);

            S2k.Argon2Params argon2Params = new S2k.Argon2Params(salt, 1, 4, 21);
            S2k argon2 = S2k.Argon2S2k(argon2Params);

            Assert.AreEqual(S2k.Argon2, argon2.Type);
            Assert.AreEqual(1, argon2.Argon2Config.Passes);
            Assert.AreEqual(4, argon2.Argon2Config.Parallelism);
            Assert.AreEqual(21, argon2.Argon2Config.MemorySizeExponent);
            Assert.AreEqual(16, argon2.Argon2Config.GetSalt().Length);

            // Test actual encoding
            MemoryStream bytes = new MemoryStream();
            BcpgOutputStream bcpgOut = new BcpgOutputStream(bytes);
            argon2.Encode(bcpgOut);
            byte[] encoding = bytes.ToArray();

            Assert.AreEqual(20, encoding.Length);
            Assert.AreEqual(0x04, encoding[0]);    // Type is Argon2
            Assert.AreEqual(0x01, encoding[17]);   // 1 pass
            Assert.AreEqual(0x04, encoding[18]);   // 4 parallelism
            Assert.AreEqual(0x15, encoding[19]);   // 0x15 = 21 mem exp
        }

        [Test]
        public void DecryptAes128Message()
        {
            string plaintext = DecryptSymmetricallyEncryptedMessage(TestMsgAes128, TestMsgPassword);
            Assert.AreEqual(TestMsgPlain, plaintext);
        }

        [Test]
        public void DecryptAes192Message()
        {
            string plaintext = DecryptSymmetricallyEncryptedMessage(TestMsgAes192, TestMsgPassword);
            Assert.AreEqual(TestMsgPlain, plaintext);
        }

        [Test]
        public void DecryptAes256Message()
        {
            string plaintext = DecryptSymmetricallyEncryptedMessage(TestMsgAes256, TestMsgPassword);
            Assert.AreEqual(TestMsgPlain, plaintext);
        }

        //[Test]
        //public void EncryptAndDecryptMessageWithArgon2()
        //{
        //    string encrypted = EncryptMessageSymmetricallyWithArgon2(TestMsgPlain, TestMsgPassword);
        //    string plaintext = DecryptSymmetricallyEncryptedMessage(encrypted, TestMsgPassword);
        //    Assert.AreEqual(TestMsgPlain, plaintext);
        //}

        [Test]
        public void CheckArgon2MaxMemoryExpValue()
        {
            Properties.WithThreadProperty(Properties.Argon2MaxMemoryExp, "10", () =>
            {
                try
                {
                    DecryptSymmetricallyEncryptedMessage(TestMsgAes256, TestMsgPassword);
                    Assert.Fail("no exception");
                }
                catch (PgpException e)
                {
                    Assert.AreEqual("memory size exponent out of range", e.Message);
                }
            });
        }

        //[Test]
        //public void CheckArgon2MaxMemoryExpValueOnSecretKey()
        //{
        //    // lock a v6 key with Argon2 (memory size exponent 16), then lower the cap and
        //    // check the bounds check also fires on the secret key decryption path
        //    Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        //    gen.Init(new Ed25519KeyGenerationParameters(Random));
        //    AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();

        //    PgpKeyPair keyPair = new PgpKeyPair(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.Ed25519, kp, DateTime.UtcNow);

        //    BcAEADSecretKeyEncryptorBuilder encBuilder = new BcAEADSecretKeyEncryptorBuilder(
        //    AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
        //    S2K.Argon2Params.memoryConstrainedParameters());

        //    PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();

        //    PGPSecretKey sk = new PGPSecretKey(
        //    keyPair.getPrivateKey(),
        //    keyPair.getPublicKey(),
        //    digestProv.get(HashAlgorithmTags.SHA1),
        //    true,
        //    encBuilder.build(TEST_MSG_PASSWORD.toCharArray(), keyPair.getPublicKey().getPublicKeyPacket()));

        //    Properties.WithThreadProperty(Properties.Argon2MaxMemoryExp, "10", () =>
        //    {
        //        try
        //        {
        //            sk.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(digestProv).build(TEST_MSG_PASSWORD.toCharArray()));
        //            Assert.Fail("no exception");
        //        }
        //        catch (PgpException e)
        //        {
        //            Assert.AreEqual("memory size exponent out of range", e.Message);
        //        }
        //    });
        //}

        private static string DecryptSymmetricallyEncryptedMessage(string message, string password)
        {
            char[] pass = password.ToCharArray();

            MemoryStream msgIn = new MemoryStream(Strings.ToByteArray(message));
            ArmoredInputStream armorIn = new ArmoredInputStream(msgIn);

            PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);
            PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)objectFactory.NextPgpObject();
            PgpPbeEncryptedData encryptedData = (PgpPbeEncryptedData)encryptedDataList[0];

            // decrypt
            Stream inputStream = encryptedData.GetDataStream(pass);
            objectFactory = new PgpObjectFactory(inputStream);
            PgpLiteralData literalData = (PgpLiteralData)objectFactory.NextPgpObject();
            Stream decryptedIn = literalData.GetDataStream();
            MemoryStream decryptedOut = new MemoryStream();
            Streams.PipeAll(decryptedIn, decryptedOut);

            return Strings.FromByteArray(decryptedOut.ToArray());
        }

        //private static string EncryptMessageSymmetricallyWithArgon2(string plaintext, string password)
        //{
        //    PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256);
        //    //encGen.addMethod(new BcPBEKeyEncryptionMethodGenerator(password.toCharArray(), S2K.Argon2Params.universallyRecommendedParameters()));
        //    encGen.AddMethod(password.ToCharArray(), S2k.Argon2Params.RecommendedParameters(Random));
        //    PgpLiteralDataGenerator litGen = new PgpLiteralDataGenerator();

        //    MemoryStream buf = new MemoryStream();
        //    ArmoredOutputStream armorOut = new ArmoredOutputStream(buf);
        //    Stream encOut = encGen.Open(armorOut, new byte[4096]);
        //    Stream litOut = litGen.Open(encOut, PgpLiteralData.Utf8, "", DateTime.UtcNow, new byte[4096]);

        //    MemoryStream plainIn = new MemoryStream(Strings.ToByteArray(plaintext));
        //    Streams.PipeAll(plainIn, litOut);
        //    litOut.Close();
        //    encOut.Close();
        //    armorOut.Close();

        //    return Strings.FromByteArray(buf.ToArray());
        //}
    }
}
