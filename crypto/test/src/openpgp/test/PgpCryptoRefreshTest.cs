using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCryptoRefreshTest
        : SimpleTest
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-4-ed25519leg
        private readonly byte[] v4Ed25519LegacyPubkeySample = Base64.Decode(
            "xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
            "Q+47JAY=");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-4-ed25519lega
        private readonly byte[] v4Ed25519LegacySignatureSample = Base64.Decode(
            "iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S" +
            "ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
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

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-secret-key
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

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-locked-version-6-sec
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

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-cleartext-signed-mes
        private readonly string v6SampleCleartextSignedMessage = "What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n";
        private readonly byte[] v6SampleCleartextSignedMessageSignature = Base64.Decode(
            "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo" +
            "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr" +
            "NK2ay45cX1IVAQ==");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-inline-signed-messag
        private readonly byte[] v6SampleInlineSignedMessage = Base64.Decode(
            "xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk" +
            "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv" +
            "bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k" +
            "bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l" +
            "JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ" +
            "b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj" +
            "FtCgazStmsuOXF9SFQE=");

        // Sample AEAD encryption and decryption - V6 SKESK + V2 SEIPD
        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-aead-eax-encryption-
        // encrypts the cleartext string Hello, world! with the passphrase password, S2K type iterated+salted,
        // using AES-128 with AEAD-EAX encryption.
        private readonly byte[] v6skesk_aes128_eax = Base64.Decode(
            "w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14" +
            "KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq" +
            "pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1" +
            "QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-aead-ocb-encryption-
        // encrypts the cleartext string Hello, world! with the passphrase password, S2K type iterated+salted,
        // using AES-128 with AEAD-OCB encryption.
        private readonly byte[] v6skesk_aes128_ocb = Base64.Decode(
            "wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl" +
            "ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM" +
            "WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0" +
            "K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-aead-gcm-encryption-
        // encrypts the cleartext string Hello, world! with the passphrase password, S2K type iterated+salted,
        // using AES-128 with AEAD-GCM encryption.
        private readonly byte[] v6skesk_aes128_gcm = Base64.Decode(
            "wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa" +
            "v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax" +
            "Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS" +
            "+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-messages-encrypted-u
        // V4 SKESK + V1 SEIPD using Argon2 (t=1, p=4, m=21) with AES-128/192/256,
        // cleartext string "Hello, world!", passphrase "password"
        private readonly byte[] v4skesk_argon2_aes128 = Base64.Decode(
            "wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+" +
            "YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH" +
            "XfA3pqV4mTzF");

        private readonly byte[] v4skesk_argon2_aes192 = Base64.Decode(
            "wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw" +
            "F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys" +
            "LVg77Mwwfgl2n/d572WciAM=");

        private readonly byte[] v4skesk_argon2_aes256 = Base64.Decode(
            "wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu" +
            "623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K" +
            "95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==");

        // V6 SKESK + V2 SEIPD using Argon2 with AES-256 in OCB mode
        // cleartext string "Hello, world!", passphrase "password"
        // Session key 9DC22B5D8DFCED080C881885335E5A1A7E1215F17BBEC0B485655A308BE3D934
        // generated with gosop 2.0.0-alpha
        private readonly byte[] v6skesk_argon2_aes256_ocb = Base64.Decode(
            "w1gGJgkCFARXue/MBMPDOPspqjeXOAwCAwQQdUzaSpJVUWXsrfYfYX6Bu+PWWSv5" +
            "v6yNbe7XcntA8BuivOCuH6FU3Mt0UJPZRO9/fRjiEGTuwg6Q7ar/gZ/N0lkCCQIM" +
            "Zjd4SG7Tv4RJHeycolKmqSHDoK5XlOsA7vlw50nKuRjDyRfsPOFDfHz8hR/z7D1i" +
            "HST68tjRCRmwqeqVgusCmBlXrXzYTkPXGtmZl2+EYazSACQFVg==");

        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-x25519-aead-ocb-encr
        // encrypts the cleartext string "Hello, world!" for the sample certificate v6Certificate
        // V6 PKESK + V2 SEIPD X25519 AES-128 OCB
        private readonly byte[] v6pkesk_v2seipd_aes128_ocb = Base64.Decode(
            "wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO" +
            "WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS" +
            "aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l" +
            "yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo" +
            "bhF30A+IitsxxA==");

        // from the "OpenPGP interoperability test suite"
        // https://tests.sequoia-pgp.org/#Encrypt-Decrypt_roundtrip_with_minimal_key_from_RFC9760
        // encrypts the cleartext string "Hello World :)" for the sample certificate v6Certificate
        // V3 PKESK + V1 SEIPD X25519 AES-256
        private readonly byte[] v3pkesk_v1seipd_aes256 = Base64.Decode(
            "wVQDEsg/HnBvYwgZEFZQspuRTLEGqQ4oEX+0ap/cDogTvDbh+Fu5K6O7ZCkpCZu4" +
            "g6JfGwkmmqn6Ekff2LPS+jcsgz4S3y+90y7zg+bw6jgy81vJYZLSPwHPmq3ld0oV" +
            "codBvOUSOAvARPpDCHvAOyMT+ZmYEbbQK/ahc3P6HGDArsfcAETvsIHBE8U45o4g" +
            "poZLYyxi0A==");

        private readonly char[] emptyPassphrase = Array.Empty<char>();

        #region "Helpers"
        private void SignVerifyRoundtrip(PgpSecretKey signingKey, char[] passphrase)
        {
            byte[] data = Encoding.UTF8.GetBytes("OpenPGP");
            byte[] wrongData = Encoding.UTF8.GetBytes("OpePGP");

            PgpSignatureGenerator sigGen = new PgpSignatureGenerator(signingKey.PublicKey.Algorithm, HashAlgorithmTag.Sha512);
            PgpSignatureSubpacketGenerator spkGen = new PgpSignatureSubpacketGenerator();
            PgpPrivateKey privKey = signingKey.ExtractPrivateKey(passphrase);
            spkGen.SetIssuerFingerprint(false, signingKey);
            sigGen.InitSign(PgpSignature.CanonicalTextDocument, privKey, new SecureRandom());
            sigGen.Update(data);
            sigGen.SetHashedSubpackets(spkGen.Generate());
            PgpSignature signature = sigGen.Generate();

            AreEqual(signature.GetIssuerFingerprint(), signingKey.GetFingerprint());

            VerifySignature(signature, data, signingKey.PublicKey);
            VerifySignature(signature, wrongData, signingKey.PublicKey, shouldFail: true);

            byte[] encodedSignature = signature.GetEncoded();
            VerifyEncodedSignature(encodedSignature, data, signingKey.PublicKey);
            VerifyEncodedSignature(encodedSignature, wrongData, signingKey.PublicKey, shouldFail: true);
        }

        private void VerifyInlineSignature(byte[] message, PgpPublicKey signer, bool shouldFail = false)
        {
            byte[] data;
            PgpObjectFactory factory = new PgpObjectFactory(message);

            PgpOnePassSignatureList p1 = factory.NextPgpObject() as PgpOnePassSignatureList;
            PgpOnePassSignature ops = p1[0];

            PgpLiteralData p2 = factory.NextPgpObject() as PgpLiteralData;
            Stream dIn = p2.GetInputStream();

            ops.InitVerify(signer);

            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[30];
                int bytesRead;
                while ((bytesRead = dIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ops.Update(buffer, 0, bytesRead);
                    ms.Write(buffer, 0, bytesRead);
                }

                data = ms.ToArray();
            }
            PgpSignatureList p3 = factory.NextPgpObject() as PgpSignatureList;
            PgpSignature sig = p3[0];

            bool result = ops.Verify(sig) != shouldFail;
            IsTrue("signature test failed", result);

            VerifySignature(sig, data, signer, shouldFail);
        }

        private void VerifySignature(PgpSignature signature, byte[] data, PgpPublicKey signer, bool shouldFail = false)
        {
            IsEquals(signature.KeyAlgorithm, signer.Algorithm);
            // the version of the signature is bound to the version of the signing key
            IsEquals(signature.Version, signer.Version);

            if (signature.KeyId != 0)
            {
                IsEquals(signature.KeyId, signer.KeyId);
            }
            byte[] issuerFpt = signature.GetIssuerFingerprint();
            if (issuerFpt != null)
            {
                IsTrue(AreEqual(issuerFpt, signer.GetFingerprint()));
            }

            signature.InitVerify(signer);
            signature.Update(data);

            bool result = signature.Verify() != shouldFail;
            IsTrue("signature test failed", result);
        }

        private void VerifyEncodedSignature(byte[] sigPacket, byte[] data, PgpPublicKey signer, bool shouldFail = false)
        {
            PgpObjectFactory factory = new PgpObjectFactory(sigPacket);
            PgpSignatureList sigList = factory.NextPgpObject() as PgpSignatureList;
            PgpSignature signature = sigList[0];

            VerifySignature(signature, data, signer, shouldFail);
        }

        private static PgpEncryptedDataGenerator CreatePgpEncryptedDataGenerator(bool useAead)
        {
            if (useAead)
            {
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, new SecureRandom());
            }
            else
            {
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
            }
        }

        private static byte[] EncryptPlaintext(PgpEncryptedDataGenerator encDataGen, byte[] plaintext, bool useBuffer)
        {
            byte[] enc;

            if (useBuffer)
            {
                byte[] buffer = new byte[1024];
                using (MemoryStream ms = new MemoryStream())
                {
                    using (Stream cOut = encDataGen.Open(ms, buffer))
                    {
                        using (BcpgOutputStream bcOut = new BcpgOutputStream(cOut, newFormatOnly: true))
                        {
                            PgpLiteralDataGenerator literalDataGen = new PgpLiteralDataGenerator();
                            DateTime modificationTime = DateTime.UtcNow;

                            using (Stream lOut = literalDataGen.Open(
                                new UncloseableStream(bcOut),
                                PgpLiteralData.Utf8,
                                PgpLiteralData.Console,
                                plaintext.Length,
                                modificationTime))
                            {
                                lOut.Write(plaintext, 0, plaintext.Length);
                            }
                        }
                    }
                    enc = ms.ToArray();
                }
            }
            else
            {
                byte[] literal;
                using (MemoryStream ms = new MemoryStream())
                {
                    PgpLiteralDataGenerator literalDataGen = new PgpLiteralDataGenerator();
                    DateTime modificationTime = DateTime.UtcNow;

                    using (Stream lOut = literalDataGen.Open(
                        new UncloseableStream(ms),
                        PgpLiteralData.Utf8,
                        PgpLiteralData.Console,
                        plaintext.Length,
                        modificationTime))
                    {
                        lOut.Write(plaintext, 0, plaintext.Length);
                    }
                    literal = ms.ToArray();
                }
                using (MemoryStream ms = new MemoryStream())
                {
                    using (Stream cOut = encDataGen.Open(ms, literal.Length))
                    {
                        cOut.Write(literal, 0, literal.Length);
                    }
                    enc = ms.ToArray();
                }
            }

            return enc;
        }

        private void SymmetricEncryptDecryptRoundtrip(byte[] plaintext, bool useAead, bool useBuffer, byte[] rawPassword)
        {
            // encrypt
            PgpEncryptedDataGenerator encDataGen = CreatePgpEncryptedDataGenerator(useAead);
            encDataGen.AddMethodRaw(rawPassword, S2k.Argon2Parameters.MemoryConstrainedParameters());
            byte[] enc = EncryptPlaintext(encDataGen, plaintext, useBuffer);

            // decrypt
            PgpObjectFactory factory = new PgpObjectFactory(enc);
            PgpEncryptedDataList encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
            FailIf("invalid PgpEncryptedDataList", encDataList is null);

            PgpPbeEncryptedData encData = encDataList[0] as PgpPbeEncryptedData;
            FailIf("invalid PgpPbeEncryptedData", encData is null);

            using (Stream stream = encData.GetDataStreamRaw(rawPassword))
            {
                factory = new PgpObjectFactory(stream);
                PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                using (MemoryStream ms = new MemoryStream())
                {
                    lit.GetDataStream().CopyTo(ms);
                    byte[] decrypted = ms.ToArray();
                    IsTrue(Arrays.AreEqual(plaintext, decrypted));
                }
            }
        }

        private void PubkeyEncryptDecryptRoundtrip(byte[] plaintext, bool useAead,bool useBuffer,  PgpPublicKey pubKey, PgpPrivateKey privKey)
        {
            // encrypt
            PgpEncryptedDataGenerator encDataGen = CreatePgpEncryptedDataGenerator(useAead);
            encDataGen.AddMethod(pubKey);
            byte[] enc = EncryptPlaintext(encDataGen, plaintext, useBuffer);

            // decrypt
            PgpObjectFactory factory = new PgpObjectFactory(enc);
            PgpEncryptedDataList encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
            FailIf("invalid PgpEncryptedDataList", encDataList is null);

            PgpPublicKeyEncryptedData encData = encDataList[0] as PgpPublicKeyEncryptedData;
            FailIf("invalid PgpPublicKeyEncryptedData", encData is null);

            using (Stream stream = encData.GetDataStream(privKey))
            {
                factory = new PgpObjectFactory(stream);
                PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                using (MemoryStream ms = new MemoryStream())
                {
                    lit.GetDataStream().CopyTo(ms);
                    byte[] decrypted = ms.ToArray();
                    IsTrue(Arrays.AreEqual(plaintext, decrypted));
                }
            }
        }
        #endregion

        [Test]
        public void Version4Ed25519LegacyPubkeySampleTest()
        {
            // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-4-ed25519leg
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v4Ed25519LegacyPubkeySample);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            IsEquals(pubKey.Algorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(pubKey.CreationTime.ToString("yyyyMMddHHmmss"), "20140819142827");
            IsEquals(pubKey.BitStrength, 256);
            byte[] expectedFingerprint = Hex.Decode("C959BDBAFA32A2F89A153B678CFDE12197965A9A");
            IsEquals((ulong)pubKey.KeyId, 0x8CFDE12197965A9A);
            IsTrue("wrong fingerprint", AreEqual(pubKey.GetFingerprint(), expectedFingerprint));
        }

        [Test]
        public void Version4Ed25519LegacyCreateTest()
        {
            // create a v4 EdDsa_Legacy Pubkey with the same key material and creation datetime as the test vector
            // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-4-ed25519leg
            // then check KeyId/Fingerprint
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
            // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-4-ed25519lega
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v4Ed25519LegacyPubkeySample);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            PgpObjectFactory factory = new PgpObjectFactory(v4Ed25519LegacySignatureSample);
            PgpSignatureList sigList = factory.NextPgpObject() as PgpSignatureList;
            PgpSignature signature = sigList[0];

            IsEquals(signature.KeyId, pubKey.KeyId);
            IsEquals(signature.KeyAlgorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(signature.HashAlgorithm, HashAlgorithmTag.Sha256);
            IsEquals(signature.CreationTime.ToString("yyyyMMddHHmmss"), "20150916122453");

            byte[] data = Encoding.UTF8.GetBytes("OpenPGP");
            VerifySignature(signature, data, pubKey);

            // test with wrong data, verification should fail
            data = Encoding.UTF8.GetBytes("OpePGP");
            VerifySignature(signature, data, pubKey, shouldFail: true);
        }

        [Test]
        public void Version6CertificateParsingTest()
        {
            /*
             * https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
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

            // Verify direct key self-signature
            PgpSignature selfSig = masterKey.GetSignatures().First();
            IsTrue(selfSig.SignatureType == PgpSignature.DirectKey);
            selfSig.InitVerify(masterKey);
            FailIf("self signature verification failed", !selfSig.VerifyCertification(masterKey));

            // subkey
            PgpPublicKey subKey = publicKeys[1];
            FailIf("wrong detection of encryption subkey", !subKey.IsEncryptionKey);
            IsEquals(subKey.Algorithm, PublicKeyAlgorithmTag.X25519);
            expectedFingerprint = Hex.Decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
            IsEquals(subKey.KeyId, 0x12C83F1E706F6308);
            IsTrue("wrong sub key fingerprint", AreEqual(subKey.GetFingerprint(), expectedFingerprint));

            // Verify subkey binding signature
            PgpSignature bindingSig = subKey.GetSignatures().First();
            IsTrue(bindingSig.SignatureType == PgpSignature.SubkeyBinding);
            bindingSig.InitVerify(masterKey);
            FailIf("subkey binding signature verification failed", !bindingSig.VerifyCertification(masterKey, subKey));

            // Encode test
            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bs = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    pubRing.Encode(bs);
                }

                byte[] encoded = ms.ToArray();
                IsTrue(AreEqual(encoded, v6Certificate));
            }
        }

        [Test]
        public void Version6PublicKeyCreationTest()
        {
            /* 
             * Create a v6 Ed25519 pubkey with the same key material and creation datetime as the test vector
             * https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
             * then check the fingerprint and verify a signature
            */
            byte[] keyMaterial = Hex.Decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
            var key = new Ed25519PublicKeyParameters(keyMaterial);
            var pubKey = new PgpPublicKey(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.Ed25519, key, DateTime.Parse("2022-11-30 16:08:03Z"));

            IsEquals(pubKey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals(pubKey.CreationTime.ToString("yyyyMMddHHmmss"), "20221130160803");
            byte[] expectedFingerprint = Hex.Decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
            IsEquals((ulong)pubKey.KeyId, 0xCB186C4F0609A697);
            IsTrue("wrong master key fingerprint", AreEqual(pubKey.GetFingerprint(), expectedFingerprint));

            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes(v6SampleCleartextSignedMessage),
                pubKey);

            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes("wrongdata"),
                pubKey,
                shouldFail: true);
        }

        [Test]
        public void Version6UnlockedSecretKeyParsingTest()
        {
            /*
             * https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
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

            SignVerifyRoundtrip(signingKey, emptyPassphrase);

            // encryption key
            PgpSecretKey encryptionKey = secretKeys[1];
            IsEquals(encryptionKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.X25519);
            IsEquals(encryptionKey.PublicKey.KeyId, 0x12C83F1E706F6308);

            // Encode-Decode roundtrip
            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bs = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    secretKeyRing.Encode(bs);
                }

                byte[] encoded = ms.ToArray();
                IsTrue(AreEqual(encoded, v6UnlockedSecretKey));
            }

            // generate and verify a v6 userid self-cert
            string userId = "Alice <alice@example.com>";
            string wrongUserId = "Bob <bob@example.com>";
            PgpSignatureGenerator sigGen = new PgpSignatureGenerator(signingKey.PublicKey.Algorithm, HashAlgorithmTag.Sha512);
            PgpPrivateKey privKey = signingKey.ExtractPrivateKey(emptyPassphrase);
            sigGen.InitSign(PgpSignature.PositiveCertification, privKey, new SecureRandom());
            PgpSignature signature = sigGen.GenerateCertification(userId, signingKey.PublicKey);
            signature.InitVerify(signingKey.PublicKey);
            if (!signature.VerifyCertification(userId, signingKey.PublicKey))
            {
                Fail("self-cert verification failed.");
            }
            signature.InitVerify(signingKey.PublicKey);
            if (signature.VerifyCertification(wrongUserId, signingKey.PublicKey))
            {
                Fail("self-cert verification failed.");
            }
            PgpPublicKey key = PgpPublicKey.AddCertification(signingKey.PublicKey, userId, signature);
            byte[] keyEnc = key.GetEncoded();
            PgpPublicKeyRing tmpRing = new PgpPublicKeyRing(keyEnc);
            key = tmpRing.GetPublicKey();
            IsTrue(key.GetUserIds().Contains(userId));

            // generate and verify a v6 cert revocation
            sigGen.InitSign(PgpSignature.KeyRevocation, privKey, new SecureRandom());
            signature = sigGen.GenerateCertification(signingKey.PublicKey);
            signature.InitVerify(signingKey.PublicKey);
            if (!signature.VerifyCertification(signingKey.PublicKey))
            {
                Fail("revocation verification failed.");
            }
            key = PgpPublicKey.AddCertification(signingKey.PublicKey, signature);
            keyEnc = key.GetEncoded();
            tmpRing = new PgpPublicKeyRing(keyEnc);
            key = tmpRing.GetPublicKey();
            IsTrue(key.IsRevoked());
        }

        [Test]
        public void Version6Ed25519KeyPairCreationTest()
        {
            /* 
             * Create a v6 Ed25519 keypair with the same key material and creation datetime as the test vector
             * https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
             * then check the fingerprint and perform encode-decode, sign-verify, encrypt-decrypt roundtrips
             */
            byte[] keyMaterial = Hex.Decode("1972817b12be707e8d5f586ce61361201d344eb266a2c82fde6835762b65b0b7");
            Ed25519PrivateKeyParameters seckey = new Ed25519PrivateKeyParameters(keyMaterial);
            Ed25519PublicKeyParameters pubkey = seckey.GeneratePublicKey();
            PgpKeyPair keypair = new PgpKeyPair(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.Ed25519, pubkey, seckey, DateTime.Parse("2022-11-30 16:08:03Z"));

            IsEquals(keypair.PublicKey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals(keypair.PublicKey.CreationTime.ToString("yyyyMMddHHmmss"), "20221130160803");
            IsEquals(keypair.PublicKey.BitStrength, 256);
            byte[] expectedFingerprint = Hex.Decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
            IsEquals((ulong)keypair.KeyId, 0xCB186C4F0609A697);
            IsTrue("wrong master key fingerprint", AreEqual(keypair.PublicKey.GetFingerprint(), expectedFingerprint));


            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes(v6SampleCleartextSignedMessage),
                keypair.PublicKey);

            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes("wrongdata"),
                keypair.PublicKey,
                shouldFail: true);

            // Encode-Decode roundtrip
            SecureRandom rand = new SecureRandom();

            PgpSignatureSubpacketGenerator spgen = new PgpSignatureSubpacketGenerator();
            spgen.SetPreferredHashAlgorithms(true, new int[] { (int)HashAlgorithmTag.Sha512, (int)HashAlgorithmTag.Sha256 });
            spgen.SetPreferredSymmetricAlgorithms(true, new int[] { (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            PgpSignatureSubpacketVector hashed = spgen.Generate();

            string uid = "Alice <alice@example.com>";
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification,
                keypair,
                uid,
                SymmetricKeyAlgorithmTag.Null,
                Array.Empty<char>(),
                false,
                hashed,
                null,
                rand);

            // add an encryption subkey
            X25519KeyPairGenerator x25519gen = new X25519KeyPairGenerator();
            x25519gen.Init(new X25519KeyGenerationParameters(rand));
            AsymmetricCipherKeyPair x25519kp = x25519gen.GenerateKeyPair();
            keypair = new PgpKeyPair(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.X25519, x25519kp, DateTime.Parse("2022-11-30 16:08:03Z"));
            keyRingGen.AddSubKey(keypair);

            PgpSecretKeyRing secring = keyRingGen.GenerateSecretKeyRing();
            
            byte[] encodedsecring = secring.GetEncoded();
            // expected length of v6 unencrypted Ed25519 secret key packet: 75 octets
            FailIf("unexpected packet length", encodedsecring[1] != 75);

            PgpSecretKeyRing decodedsecring = new PgpSecretKeyRing(encodedsecring);

            PgpPublicKey pgppubkey = decodedsecring.GetPublicKey();
            PgpSecretKey pgpseckey = decodedsecring.GetSecretKey();
            IsEquals(pgppubkey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals(pgppubkey.CreationTime.ToString("yyyyMMddHHmmss"), "20221130160803");
            IsEquals((ulong)pgppubkey.KeyId, 0xCB186C4F0609A697);
            IsTrue("wrong master key fingerprint", AreEqual(pgppubkey.GetFingerprint(), expectedFingerprint));
            IsTrue(pgppubkey.GetUserIds().Contains(uid));

            // verify selfsig
            PgpSignature signature = pgppubkey.GetSignaturesForId(uid).ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version6);
            IsEquals(signature.SignatureType, PgpSignature.PositiveCertification);
            signature.InitVerify(pgppubkey);
            IsTrue(signature.VerifyCertification(uid, pgppubkey));
            IsTrue(!signature.VerifyCertification("Bob <bob@example.com>", pgppubkey));

            // verify subkey
            PgpSecretKey subKey = decodedsecring.GetSecretKeys().ToArray()[1];
            IsEquals(subKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.X25519);

            // Verify subkey binding signature
            PgpSignature bindingSig = subKey.PublicKey.GetSignatures().First();
            IsTrue(bindingSig.SignatureType == PgpSignature.SubkeyBinding);
            bindingSig.InitVerify(pgppubkey);
            IsTrue("subkey binding signature verification failed", bindingSig.VerifyCertification(pgppubkey, subKey.PublicKey));

            // Sign-Verify roundtrip
            SignVerifyRoundtrip(pgpseckey, emptyPassphrase);

            // encrypt-decrypt roundtrip
            // V3 PKESK + V1 SEIPD
            PubkeyEncryptDecryptRoundtrip(
                Encoding.UTF8.GetBytes("Hello, World!"),
                false,
                false,
                subKey.PublicKey,
                subKey.ExtractPrivateKey(emptyPassphrase));

            // V6 PKESK + V2 SEIPD
            PubkeyEncryptDecryptRoundtrip(
                Encoding.UTF8.GetBytes("Hello, World!"),
                true,
                false,
                subKey.PublicKey,
                subKey.ExtractPrivateKey(emptyPassphrase));

            PgpPublicKeyRing pubring = keyRingGen.GeneratePublicKeyRing();
            PgpPublicKey[] keys = pubring.GetPublicKeys().ToArray();
            IsEquals(keys[0].Version, PublicKeyPacket.Version6);
            IsEquals(keys[0].Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsTrue("wrong master key fingerprint", AreEqual(keys[0].GetFingerprint(), expectedFingerprint));
            IsEquals(keys[1].Version, PublicKeyPacket.Version6);
            IsEquals(keys[1].Algorithm, PublicKeyAlgorithmTag.X25519);
        }

        [Test]
        public void Version6Ed448KeyPairCreationTest()
        {
            /* 
             * Create a v6 Ed448 keypair, then perform encode-decode, sign-verify, encrypt-decrypt roundtrips
             */
            SecureRandom rand = new SecureRandom();
            DateTime now = DateTime.UtcNow;

            Ed448KeyPairGenerator ed448gen = new Ed448KeyPairGenerator();
            ed448gen.Init(new Ed448KeyGenerationParameters(rand));
            AsymmetricCipherKeyPair kp = ed448gen.GenerateKeyPair();

            PgpKeyPair keypair = new PgpKeyPair(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.Ed448, kp, now);
            IsEquals(keypair.PublicKey.Algorithm, PublicKeyAlgorithmTag.Ed448);
            IsEquals(keypair.PublicKey.CreationTime.ToString("yyyyMMddHHmmss"), now.ToString("yyyyMMddHHmmss"));
            IsEquals(keypair.PublicKey.BitStrength, 448);
            long keyId = keypair.PublicKey.KeyId;
            byte[] fpr = keypair.PublicKey.GetFingerprint();
            IsEquals(fpr.Length, 32);

            // encode-decode roundtrip
            string uid = "Alice <alice@example.com>";
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.PositiveCertification,
                keypair,
                uid,
                SymmetricKeyAlgorithmTag.Null,
                Array.Empty<char>(),
                false,
                null,
                null,
                rand);

            // add an encryption subkey
            X448KeyPairGenerator x448gen = new X448KeyPairGenerator();
            x448gen.Init(new X448KeyGenerationParameters(rand));
            AsymmetricCipherKeyPair x448kp = x448gen.GenerateKeyPair();
            keypair = new PgpKeyPair(PublicKeyPacket.Version6, PublicKeyAlgorithmTag.X448, x448kp, now);
            keyRingGen.AddSubKey(keypair);

            PgpSecretKeyRing secring = keyRingGen.GenerateSecretKeyRing();

            byte[] encodedsecring = secring.GetEncoded();
            // expected length of v6 unencrypted Ed448 secret key packet: 125 octets
            FailIf("unexpected packet length", encodedsecring[1] != 125);

            PgpSecretKeyRing decodedsecring = new PgpSecretKeyRing(encodedsecring);

            PgpPublicKey pgppubkey = decodedsecring.GetPublicKey();
            PgpSecretKey pgpseckey = decodedsecring.GetSecretKey();
            IsEquals(pgppubkey.Algorithm, PublicKeyAlgorithmTag.Ed448);
            IsEquals(pgppubkey.CreationTime.ToString("yyyyMMddHHmmss"), now.ToString("yyyyMMddHHmmss"));
            IsEquals(pgppubkey.KeyId, keyId);
            IsTrue("wrong master key fingerprint", AreEqual(pgppubkey.GetFingerprint(), fpr));
            IsTrue(pgppubkey.GetUserIds().Contains(uid));

            // verify selfsig
            PgpSignature signature = pgppubkey.GetSignaturesForId(uid).ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version6);
            IsEquals(signature.SignatureType, PgpSignature.PositiveCertification);
            signature.InitVerify(pgppubkey);
            IsTrue(signature.VerifyCertification(uid, pgppubkey));
            IsTrue(!signature.VerifyCertification("Bob <bob@example.com>", pgppubkey));

            // verify subkey
            PgpSecretKey subKey = decodedsecring.GetSecretKeys().ToArray()[1];
            IsEquals(subKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.X448);

            // Verify subkey binding signature
            PgpSignature bindingSig = subKey.PublicKey.GetSignatures().First();
            IsTrue(bindingSig.SignatureType == PgpSignature.SubkeyBinding);
            bindingSig.InitVerify(pgppubkey);
            IsTrue("subkey binding signature verification failed", bindingSig.VerifyCertification(pgppubkey, subKey.PublicKey));

            // Sign-Verify roundtrip
            SignVerifyRoundtrip(pgpseckey, emptyPassphrase);

            // Encrypt-Decrypt roundtrip
            PubkeyEncryptDecryptRoundtrip(
                Encoding.UTF8.GetBytes("Hello, World!"),
                false,
                false,
                subKey.PublicKey,
                subKey.ExtractPrivateKey(emptyPassphrase));

            PgpPublicKeyRing pubring = keyRingGen.GeneratePublicKeyRing();
            PgpPublicKey[] keys = pubring.GetPublicKeys().ToArray();
            IsEquals(keys[0].Version, PublicKeyPacket.Version6);
            IsEquals(keys[0].Algorithm, PublicKeyAlgorithmTag.Ed448);
            IsTrue("wrong master key fingerprint", AreEqual(keys[0].GetFingerprint(), fpr));
            IsEquals(keys[1].Version, PublicKeyPacket.Version6);
            IsEquals(keys[1].Algorithm, PublicKeyAlgorithmTag.X448);

            using (var ms = new MemoryStream())
            {
                using (var arms = new ArmoredOutputStream(ms))
                {
                    decodedsecring.Encode(arms);
                }
                string armored = Encoding.ASCII.GetString(ms.ToArray());
            }

            using (var ms = new MemoryStream())
            {
                using (var arms = new ArmoredOutputStream(ms))
                {
                    pubring.Encode(arms);
                }
                string armored = Encoding.ASCII.GetString(ms.ToArray());
            }
        }

        [Test]
        public void Version6LockedSecretKeyParsingTest()
        {
            /*
             * https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
             * The same secret key as in Version6UnlockedSecretKeyParsingTest, but the secret key
             * material is locked with a passphrase using AEAD and Argon2.
             */

            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(v6LockedSecretKey);
            PgpSecretKey[] secretKeys = secretKeyRing.GetSecretKeys().ToArray();
            IsEquals("wrong number of secret keys", secretKeys.Length, 2);

            // signing key
            PgpSecretKey signingKey = secretKeys[0];
            IsEquals(signingKey.KeyEncryptionAlgorithm, SymmetricKeyAlgorithmTag.Aes256);
            IsEquals(signingKey.KeyEncryptionAeadAlgorithm, AeadAlgorithmTag.Ocb);
            IsEquals(signingKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.Ed25519);
            IsEquals((ulong)signingKey.PublicKey.KeyId, 0xCB186C4F0609A697);

            // try to decrypt with wrong passphrases
            Assert.Throws<PgpException>(() =>
            {
                PgpPrivateKey pk = signingKey.ExtractPrivateKey(emptyPassphrase);
            });
            Assert.Throws<PgpException>(() =>
            {
                PgpPrivateKey pk = signingKey.ExtractPrivateKey("wrong".ToCharArray());
            });

            string passphrase = "correct horse battery staple";
            SignVerifyRoundtrip(signingKey, passphrase.ToCharArray());

            // encryption key
            PgpSecretKey encryptionKey = secretKeys[1];
            IsEquals(encryptionKey.KeyEncryptionAlgorithm, SymmetricKeyAlgorithmTag.Aes256);
            IsEquals(encryptionKey.KeyEncryptionAeadAlgorithm, AeadAlgorithmTag.Ocb);
            IsEquals(encryptionKey.PublicKey.Algorithm, PublicKeyAlgorithmTag.X25519);
            IsEquals(encryptionKey.PublicKey.KeyId, 0x12C83F1E706F6308);

            // encrypt-decrypt
            PubkeyEncryptDecryptRoundtrip(
                Encoding.UTF8.GetBytes("Hello, World!"),
                false,
                false,
                encryptionKey.PublicKey,
                encryptionKey.ExtractPrivateKey(passphrase.ToCharArray()));

            // Encode-Decode roundtrip
            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bs = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    secretKeyRing.Encode(bs);
                }

                byte[] encoded = ms.ToArray();
                IsTrue(AreEqual(encoded, v6LockedSecretKey));
            }
        }

        [Test]
        public void Version6SampleCleartextSignedMessageVerifySignatureTest()
        {
            // https://www.rfc-editor.org/rfc/rfc9580#name-sample-cleartext-signed-mes
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v6Certificate);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes(v6SampleCleartextSignedMessage),
                pubKey);

            VerifyEncodedSignature(
                v6SampleCleartextSignedMessageSignature,
                Encoding.UTF8.GetBytes("wrongdata"),
                pubKey,
                shouldFail: true);
        }

        [Test]
        public void Version6SampleInlineSignedMessageVerifySignatureTest()
        {
            // https://www.rfc-editor.org/rfc/rfc9580#name-sample-inline-signed-messag
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v6Certificate);
            PgpPublicKey pubKey = pubRing.GetPublicKey();

            VerifyInlineSignature(v6SampleInlineSignedMessage, pubKey);
        }

        [Test]
        public void Version6GenerateAndVerifyInlineSignatureTest()
        {
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(v6UnlockedSecretKey);
            PgpSecretKey signingKey = secretKeyRing.GetSecretKey();
            PgpPrivateKey privKey = signingKey.ExtractPrivateKey(emptyPassphrase);
            byte[] data = Encoding.UTF8.GetBytes("OpenPGP\nOpenPGP");
            byte[] inlineSignatureMessage;

            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bcOut = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    PgpSignatureGenerator sGen = new PgpSignatureGenerator(signingKey.PublicKey.Algorithm, HashAlgorithmTag.Sha384);
                    sGen.InitSign(PgpSignature.CanonicalTextDocument, privKey, new SecureRandom());
                    sGen.GenerateOnePassVersion(false).Encode(bcOut);

                    PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
                    DateTime modificationTime = DateTime.UtcNow;
                    using (var lOut = lGen.Open(
                        new UncloseableStream(bcOut),
                        PgpLiteralData.Utf8,
                        "_CONSOLE",
                        data.Length,
                        modificationTime))
                    {
                        lOut.Write(data, 0, data.Length);
                        sGen.Update(data);
                    }

                    sGen.Generate().Encode(bcOut);
                }

                inlineSignatureMessage = ms.ToArray();
            }

            VerifyInlineSignature(inlineSignatureMessage, signingKey.PublicKey);
            // corrupt data
            inlineSignatureMessage[88] = 80;
            VerifyInlineSignature(inlineSignatureMessage, signingKey.PublicKey, shouldFail: true);
        }

        [Test]
        public void Version6SkeskVersion2SeipdTest()
        {
            // encrypts the cleartext string "Hello, world!" with the passphrase "password",
            // S2K type iterated+salted, using AES-128 with AEAD encryption.
            byte[][] messages = new byte[][]
            {
                v6skesk_aes128_eax,   // from RFC 9580 A.9
                v6skesk_aes128_ocb,   // from RFC 9580 A.10
                v6skesk_aes128_gcm    // from RFC 9580 A.11
            };

            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, world!");
            byte[] password = Encoding.UTF8.GetBytes("password");

            for (int i = 0; i < messages.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(messages[i]);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPbeEncryptedData;
                FailIf("invalid PgpPbeEncryptedData", encData0 is null);

                using (var stream = encData0.GetDataStreamRaw(password))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }

            // wrong passsword
            byte[] wrongpassword = Encoding.UTF8.GetBytes("wrongpassword");
            for (int i = 0; i < messages.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(messages[i]);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(wrongpassword);
                });
            }

            for (int i = 0; i < messages.Length; i++)
            {
                // corrupt AEAD nonce
                var message = Arrays.Clone(messages[i]);
                message[0x18]--;
                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(password);
                });
            }

            for (int i = 0; i < messages.Length; i++)
            {
                // corrupt encrypted session key
                var message = Arrays.Clone(messages[i]);
                message[0x28]--;
                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(password);
                });
            }

            for (int i = 0; i < messages.Length; i++)
            {
                // corrupt chunk #0 encrypted data
                var message = Arrays.Clone(messages[i]);
                message[message.Length - 35]--;
                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(password);
                });
            }

            for (int i = 0; i < messages.Length; i++)
            {
                // corrupt chunk #0 authtag
                var message = Arrays.Clone(messages[i]);
                message[message.Length - 20]--;
                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(password);
                });
            }

            for (int i = 0; i < messages.Length; i++)
            {
                // corrupt final authtag
                var message = Arrays.Clone(messages[i]);
                message[message.Length-2]--;
                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(password);
                });
            }

            /*
             *  V6 SKESK + V2 SEIPD AEAD encrypted message that spans over 4 chunks
             *  (chunk size 512 octets)
             *  2000 octets of /dev/zero encrypted with password "password" using Argon2
             *  and AES-256 in OCB mode. Generated with gosop 2.0.0-alpha
             *  Session key A96F671431CEB0F859CFC653976417CCC4126BC0F93C30C6E5F0073E0B91E65A
             */
            {
                plaintext = new byte[2000];
                Arrays.Fill(plaintext, 0);

                Stream message = PgpUtilities.GetDecoderStream(
                    SimpleTest.GetTestDataAsStream("openpgp.big-skesk-aead-msg.asc"));

                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPbeEncryptedData;
                FailIf("invalid PgpPbeEncryptedData", encData0 is null);

                using (var stream = encData0.GetDataStreamRaw(password))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }
        }

        [Test]
        public void SkeskWithArgon2Test()
        {
            byte[][] messages = new byte[][]
            {
                v4skesk_argon2_aes128,    // from RFC 9580 A.12.1
                v4skesk_argon2_aes192,    // from RFC 9580 A.12.2
                v4skesk_argon2_aes256,    // from RFC 9580 A.12.3
                v6skesk_argon2_aes256_ocb // generated with gosop 2.0.0-alpha
            };

            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, world!");
            byte[] password = Encoding.UTF8.GetBytes("password");

            for (int i = 0; i < messages.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(messages[i]);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPbeEncryptedData;
                FailIf("invalid PgpPbeEncryptedData", encData0 is null);

                using (var stream = encData0.GetDataStreamRaw(password))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }

            // wrong passsword
            byte[] wrongpassword = Encoding.UTF8.GetBytes("wrongpassword");
            for (int i = 0; i < messages.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(messages[i]);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                var encData0 = encData[0] as PgpPbeEncryptedData;
                var err = Assert.Throws<PgpException>(() =>
                {
                    var stream = encData0.GetDataStreamRaw(wrongpassword);
                });
            }

            // encrypt-decrypt roundtrip
            byte[] largePlaintext = new byte[50000];
            Arrays.Fill(largePlaintext, 0);
            // V4 SKESK + V1 SEIPD
            //    Using length in PgpEncryptedDataGenerator.Open
            SymmetricEncryptDecryptRoundtrip(plaintext, false, false, password);
            SymmetricEncryptDecryptRoundtrip(largePlaintext, false, false, password);
            //    Using buffer in PgpEncryptedDataGenerator.Open
            SymmetricEncryptDecryptRoundtrip(plaintext, false, true, password);
            SymmetricEncryptDecryptRoundtrip(largePlaintext, false, true, password);
            // AEAD V6 SKESK + V2 SEIPD
            //    Using length
            SymmetricEncryptDecryptRoundtrip(plaintext, true, false, password);
            SymmetricEncryptDecryptRoundtrip(largePlaintext, true, false, password);
            //    Using buffer
            SymmetricEncryptDecryptRoundtrip(plaintext, true, true, password);
            SymmetricEncryptDecryptRoundtrip(largePlaintext, true, true, password);
        }


        [Test]
        public void PkeskTest()
        {
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(v6UnlockedSecretKey);
            PgpSecretKey[] secretKeys = secretKeyRing.GetSecretKeys().ToArray();
            PgpSecretKey encryptionSubkey = secretKeys[1];
            PgpPrivateKey privKey = encryptionSubkey.ExtractPrivateKey(emptyPassphrase);

            // V6 PKESK + V2 SEIPD X25519 AES-128 OCB
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("Hello, world!");
                PgpObjectFactory factory = new PgpObjectFactory(v6pkesk_v2seipd_aes128_ocb);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPublicKeyEncryptedData;
                FailIf("invalid PgpPublicKeyEncryptedData", encData0 is null);

                IsEquals(encryptionSubkey.KeyId, encData0.KeyId);
                IsTrue(Arrays.AreEqual(encryptionSubkey.GetFingerprint(), encData0.GetKeyFingerprint()));
                IsEquals(SymmetricKeyAlgorithmTag.Aes128, encData0.GetSymmetricAlgorithm(privKey));

                using (var stream = encData0.GetDataStream(privKey))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }

            /*
             *  V6 PKESK + V2 SEIPD AEAD encrypted message that spans over 4 chunks
             *  (chunk size 512 octets)
             *  2000 octets of /dev/zero encrypted with sample V6 certificate from
             *  RFC 9580 Appendix A.3 and AES-256 in OCB mode.
             *  Generated with gosop 2.0.0-alpha
             *  Session key CFB73D46CF7C13B7535227BEDB5B2D8B4023C5B58289D19CF2C33B0DB388B0B6
             */
            {
                var plaintext = new byte[2000];
                Arrays.Fill(plaintext, 0);

                Stream message = PgpUtilities.GetDecoderStream(
                    SimpleTest.GetTestDataAsStream("openpgp.big-pkesk-aead-msg.asc"));

                PgpObjectFactory factory = new PgpObjectFactory(message);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPublicKeyEncryptedData;
                FailIf("invalid PgpPublicKeyEncryptedData", encData0 is null);

                IsEquals(encryptionSubkey.KeyId, encData0.KeyId);
                IsEquals(SymmetricKeyAlgorithmTag.Aes256, encData0.GetSymmetricAlgorithm(privKey));

                using (var stream = encData0.GetDataStream(privKey))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }

            // V3 PKESK + V1 SEIPD X25519 AES-256
            {
                byte[] plaintext = Encoding.UTF8.GetBytes("Hello World :)");
                PgpObjectFactory factory = new PgpObjectFactory(v3pkesk_v1seipd_aes256);
                PgpEncryptedDataList encData = factory.NextPgpObject() as PgpEncryptedDataList;
                FailIf("invalid PgpEncryptedDataList", encData is null);

                var encData0 = encData[0] as PgpPublicKeyEncryptedData;
                FailIf("invalid PgpPublicKeyEncryptedData", encData0 is null);

                IsEquals(encryptionSubkey.KeyId, encData0.KeyId);
                IsEquals(SymmetricKeyAlgorithmTag.Aes256, encData0.GetSymmetricAlgorithm(privKey));

                using (var stream = encData0.GetDataStream(privKey))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (var ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        var decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(plaintext, decrypted));
                    }
                }
            }

            // encrypt-decrypt roundtrip
            {
                byte[] shortPlaintext = Encoding.UTF8.GetBytes("Hello, world!");
                byte[] largePlaintext = new byte[50000];
                Arrays.Fill(largePlaintext, 0);

                PgpPublicKeyRing publicKeyRing = new PgpPublicKeyRing(v6Certificate);
                PgpPublicKey pubKey = publicKeyRing.GetPublicKeys().First(k => k.IsEncryptionKey);

                // V3 PKESK + V1 SEIPD X25519
                //    Using length in PgpEncryptedDataGenerator.Open
                PubkeyEncryptDecryptRoundtrip(shortPlaintext, false, false, pubKey, privKey);
                PubkeyEncryptDecryptRoundtrip(largePlaintext, false, false, pubKey, privKey);
                //    Using buffer in PgpEncryptedDataGenerator.Open
                PubkeyEncryptDecryptRoundtrip(shortPlaintext, false, true, pubKey, privKey);
                PubkeyEncryptDecryptRoundtrip(largePlaintext, false, true, pubKey, privKey);

                // V6 PKESK + V2 SEIPD X25519
                //    Using length
                PubkeyEncryptDecryptRoundtrip(shortPlaintext, true, false, pubKey, privKey);
                PubkeyEncryptDecryptRoundtrip(largePlaintext, true, false, pubKey, privKey);
                //    Using buffer
                PubkeyEncryptDecryptRoundtrip(shortPlaintext, true, true, pubKey, privKey);
                PubkeyEncryptDecryptRoundtrip(largePlaintext, true, true, pubKey, privKey);
            }
        }

        public override string Name => "PgpCryptoRefreshTest";

        public override void PerformTest()
        {
            Version4Ed25519LegacyPubkeySampleTest();
            Version4Ed25519LegacySignatureSampleTest();
            Version4Ed25519LegacyCreateTest();
            Version6CertificateParsingTest();
            Version6PublicKeyCreationTest();
            Version6Ed25519KeyPairCreationTest();
            Version6Ed448KeyPairCreationTest();
            Version6UnlockedSecretKeyParsingTest();
            Version6LockedSecretKeyParsingTest();
            Version6SampleCleartextSignedMessageVerifySignatureTest();
            Version6SampleInlineSignedMessageVerifySignatureTest();
            Version6GenerateAndVerifyInlineSignatureTest();
            Version6SkeskVersion2SeipdTest();
            SkeskWithArgon2Test();
            PkeskTest();
        }
    }
}