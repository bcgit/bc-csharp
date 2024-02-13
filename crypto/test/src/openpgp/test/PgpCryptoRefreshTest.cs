using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCryptoRefreshTest
        : SimpleTest
    {
        public override string Name => "PgpCryptoRefreshTest";


        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-key
        private readonly byte[] v4Ed25519LegacyPubkeySample = Base64.Decode(
            "xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
            "Q+47JAY=");

        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-sig
        private readonly byte[] v4Ed25519LegacySignatureSample = Base64.Decode(
            "iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S" +
            "ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE");

        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        private readonly byte[] v6Certificate = Base64.Decode(
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==");

        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
        private readonly byte[] v6UnlockedSecretKey = Base64.Decode(
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr" +
            "k0mXubZvyl4GBg==");

        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-locked-v6-secret-key
        private readonly byte[] v6LockedSecretKey = Base64.Decode(
            "xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC" +
            "FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS" +
            "3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC" +
            "Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW" +
            "cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin" +
            "7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/" +
            "0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0" +
            "gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf" +
            "9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR" +
            "v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr" +
            "DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki" +
            "Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt" +
            "ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG");

        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-cleartext-signed-mes
        private readonly string v6SampleCleartextSignedMessage = "What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n";
        private readonly byte[] v6SampleCleartextSignedMessageSignature = Base64.Decode(
            "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo" +
            "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr" +
            "NK2ay45cX1IVAQ==");

        [Test]
        public void Version4Ed25519LegacyPubkeySampleTest()
        {
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-key
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v4Ed25519LegacyPubkeySample);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            IsEquals(pubKey.Algorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(pubKey.CreationTime.ToString("yyyyMMddHHmmss"), "20140819142827");

            byte[] expectedFingerprint = Hex.Decode("C959BDBAFA32A2F89A153B678CFDE12197965A9A");
            IsEquals((ulong)pubKey.KeyId, 0x8CFDE12197965A9A);
            IsTrue("wrong fingerprint", AreEqual(pubKey.GetFingerprint(), expectedFingerprint));
        }

        [Test]
        public void Version4Ed25519LegacyCreateTest()
        {
            var key = new Ed25519PublicKeyParameters(Hex.Decode("3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406"));
            var pubKey = new PgpPublicKey(PublicKeyAlgorithmTag.EdDsa_Legacy, key, DateTime.Parse("2014-08-19 14:28:27Z"));
            IsEquals(pubKey.Algorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(pubKey.CreationTime.ToString("yyyyMMddHHmmss"), "20140819142827");

            byte[] expectedFingerprint = Hex.Decode("C959BDBAFA32A2F89A153B678CFDE12197965A9A");
            IsEquals((ulong)pubKey.KeyId, 0x8CFDE12197965A9A);
            IsTrue("wrong fingerprint", AreEqual(pubKey.GetFingerprint(), expectedFingerprint));
        }

        [Test]
        public void Version4Ed25519LegacySignatureSampleTest()
        {
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-sig
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v4Ed25519LegacyPubkeySample);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            PgpObjectFactory factory = new PgpObjectFactory(v4Ed25519LegacySignatureSample);
            PgpSignatureList sigList = (PgpSignatureList)factory.NextPgpObject();
            PgpSignature signature = sigList[0];

            IsEquals(signature.KeyId, pubKey.KeyId);
            IsEquals(signature.KeyAlgorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(signature.HashAlgorithm, HashAlgorithmTag.Sha256);
            IsEquals(signature.CreationTime.ToString("yyyyMMddHHmmss"), "20150916122453");

            byte[] original = Encoding.UTF8.GetBytes("OpenPGP");
            signature.InitVerify(pubKey);
            signature.Update(original);
            
            IsTrue("Failed generated signature check against original data", signature.Verify());
        }

        [Test]
        public void Version6CertificateParsingTest()
        {
            /*
             * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
             * A Transferable Public Key consisting of:
             *     A v6 Ed25519 Public-Key packet
             *     A v6 direct key self-signature
             *     A v6 X25519 Public-Subkey packet
             *     A v6 subkey binding signature
             */
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v6Certificate);
            PgpPublicKey[] publicKeys = pubRing.GetPublicKeys().ToArray();
            IsEquals("wrong number of public keys", publicKeys.Length, 2);

            // master key
            PgpPublicKey masterKey = publicKeys[0];
            FailIf("wrong detection of master key", !masterKey.IsMasterKey);
            IsEquals(masterKey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals(masterKey.CreationTime.ToString("yyyyMMddHHmmss"), "20221130160803");
            byte[] expectedFingerprint = Hex.Decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
            IsEquals((ulong)masterKey.KeyId, 0xCB186C4F0609A697);
            IsTrue("wrong master key fingerprint", AreEqual(masterKey.GetFingerprint(), expectedFingerprint));

            // TODO Verify self signatures

            // subkey
            PgpPublicKey subKey = publicKeys[1];
            FailIf("wrong detection of encryption subkey", !subKey.IsEncryptionKey);
            IsEquals(subKey.Algorithm, PublicKeyAlgorithmTag.X25519);
            expectedFingerprint = Hex.Decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
            IsEquals(subKey.KeyId, 0x12C83F1E706F6308);
            IsTrue("wrong sub key fingerprint", AreEqual(subKey.GetFingerprint(), expectedFingerprint));

            // TODO Verify subkey binding signature
        }

        [Test]
        public void Version6UnlockedSecretKeyParsingTest()
        {
            /*
             * https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
             * A Transferable Secret Key consisting of:
             *     A v6 Ed25519 Secret-Key packet
             *     A v6 direct key self-signature
             *     A v6 X25519 Secret-Subkey packet
             *     A v6 subkey binding signature
             */

            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(v6UnlockedSecretKey);
            PgpSecretKey[] secretKeys = secretKeyRing.GetSecretKeys().ToArray();
            IsEquals("wrong number of secret keys", secretKeys.Length, 2);

            // signing key
            PgpSecretKey signingKey = secretKeys[0];
            IsEquals(signingKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals((ulong)signingKey.PublicKey.KeyId, 0xCB186C4F0609A697);

            AsymmetricCipherKeyPair signingKeyPair = GetKeyPair(signingKey);
            IsTrue("signature test failed", SignThenVerifyEd25519Test(signingKeyPair));

            // encryption key
            PgpSecretKey encryptionKey = secretKeys[1];
            IsEquals(encryptionKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.X25519);
            IsEquals(encryptionKey.PublicKey.KeyId, 0x12C83F1E706F6308);

            AsymmetricCipherKeyPair alice = GetKeyPair(encryptionKey);
            IAsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair bob = kpGen.GenerateKeyPair();

            IsTrue("X25519 agreement failed", EncryptThenDecryptX25519Test(alice, bob));
        }

        [Test]
        public void Version6SampleCleartextSignedMessageVerifySignatureTest()
        {
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-cleartext-signed-mes

            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v6Certificate);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            PgpObjectFactory factory = new PgpObjectFactory(v6SampleCleartextSignedMessageSignature);
            PgpSignatureList sigList = (PgpSignatureList)factory.NextPgpObject();
            PgpSignature signature = sigList[0];

            byte[] data = Encoding.UTF8.GetBytes(v6SampleCleartextSignedMessage);
            signature.InitVerify(pubKey);
            signature.Update(data);

            IsTrue("Failed generated signature check against original data", signature.Verify());
        }

        private static AsymmetricCipherKeyPair GetKeyPair(PgpSecretKey secretKey, string password = "")
        {
            return new AsymmetricCipherKeyPair(
                secretKey.PublicKey.GetKey(),
                secretKey.ExtractPrivateKey(password.ToCharArray()).Key);
        }

        private static bool SignThenVerifyEd25519Test(AsymmetricCipherKeyPair signingKeyPair)
        {
            byte[] data = Encoding.UTF8.GetBytes("OpenPGP");

            ISigner signer = new Ed25519Signer();
            signer.Init(true, signingKeyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signature = signer.GenerateSignature();

            signer.Init(false, signingKeyPair.Public);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        private static bool EncryptThenDecryptX25519Test(AsymmetricCipherKeyPair alice, AsymmetricCipherKeyPair bob)
        {
            X25519Agreement agreeA = new X25519Agreement();
            agreeA.Init(alice.Private);
            byte[] secretA = new byte[agreeA.AgreementSize];
            agreeA.CalculateAgreement(bob.Public, secretA, 0);

            X25519Agreement agreeB = new X25519Agreement();
            agreeB.Init(bob.Private);
            byte[] secretB = new byte[agreeB.AgreementSize];
            agreeB.CalculateAgreement(alice.Public, secretB, 0);

            return Arrays.AreEqual(secretA, secretB);
        }

        public override void PerformTest()
        {
            Version4Ed25519LegacyPubkeySampleTest();
            Version4Ed25519LegacySignatureSampleTest();
            Version6CertificateParsingTest();
            Version6UnlockedSecretKeyParsingTest();
            Version6SampleCleartextSignedMessageVerifySignatureTest();
        }
    }
}