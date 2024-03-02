using NUnit.Framework;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpInteroperabilityTestSuite
        : SimpleTest
    {
        // v4 key "Alice" from "OpenPGP Example Keys and Certificates"
        // https://www.ietf.org/archive/id/draft-bre-openpgp-samples-01.html#name-alices-ed25519-samples
        private static readonly byte[] alicePubkey = Base64.Decode(
            "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U" +
            "b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE" +
            "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy" +
            "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO" +
            "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4" +
            "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s" +
            "E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb" +
            "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn" +
            "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=");

        private static readonly byte[] aliceSecretkey = Base64.Decode(
            "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U" +
            "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj" +
            "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ" +
            "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l" +
            "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf" +
            "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB" +
            "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA" +
            "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF" +
            "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM" +
            "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb" +
            "Pnn+We1aTBhaGa86AQ==");

        // v6 keys from crypto-refresh
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
        private static readonly byte[] v6Certificate = Base64.Decode(
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==");

        private static readonly byte[] v6UnlockedSecretKey = Base64.Decode(
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

        // v5 keys from "OpenPGP interoperability test suite"
        // https://tests.sequoia-pgp.org/#Inline_Sign-Verify_roundtrip_with_key__Emma_
        private static readonly byte[] v5Certificate = Base64.Decode(
            "mDcFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd" +
            "fj75iux+my8QtBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0" +
            "e8mHJGQCX5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyIC" +
            "AQYVCgkICwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3w" +
            "wJAXRJy9M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2Bbg8BVyR" +
            "9OQSAAAAMgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0" +
            "YvYWWAoDAQgHiHoFGBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACR" +
            "WVabVAUCXJH05AIbDAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijho" +
            "b2U5AQC+RtOHCHx7TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==");

        private static readonly byte[] v5UnlockedSecretKey = Base64.Decode(
            "lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd" +
            "fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA" +
            "Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC" +
            "X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI" +
            "CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9" +
            "M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA" +
            "MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD" +
            "AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF" +
            "GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb" +
            "DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7" +
            "TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==");

        private static readonly char[] emptyPassphrase = Array.Empty<char>();

        private static PgpSignatureGenerator CreateAndInitPgpSignatureGenerator(PgpSecretKey signingKey, HashAlgorithmTag hashAlgo, char[] passphrase)
        {
            PgpSignatureGenerator generator = new PgpSignatureGenerator(signingKey.PublicKey.Algorithm, hashAlgo);
            PgpPrivateKey privKey = signingKey.ExtractPrivateKey(passphrase);
            generator.InitSign(PgpSignature.CanonicalTextDocument, privKey, new SecureRandom());

            return generator;
        }

        private static PgpPublicKeyRingBundle CreateBundle(params PgpPublicKeyRing[] keyrings)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (var keyring in keyrings)
                {
                    keyring.Encode(ms);
                }
                return new PgpPublicKeyRingBundle(ms.ToArray());
            }
        }

        private void VerifyMultipleInlineSignaturesTest(byte[] message, PgpPublicKeyRingBundle bundle, bool shouldFail = false)
        {
            PgpObjectFactory factory = new PgpObjectFactory(message);
            PgpOnePassSignatureList opss = factory.NextPgpObject() as PgpOnePassSignatureList;
            for (int i = 0; i < opss.Count; i++)
            {
                PgpOnePassSignature ops = opss[i];
                ops.InitVerify(bundle.GetPublicKey(ops.KeyId));
            }

            PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
            using (Stream dIn = lit.GetInputStream())
            {

                byte[] buffer = new byte[30];
                int bytesRead;
                while ((bytesRead = dIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < opss.Count; i++)
                    {
                        opss[i].Update(buffer, 0, bytesRead);
                    }
                }
            }

            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;
            IsEquals(opss.Count, sigs.Count);
            int sigCount = sigs.Count - 1;
            for (int i = 0; i <= sigCount; i++)
            {
                IsTrue(shouldFail != opss[i].Verify(sigs[sigCount - i]));
            }
        }

        [Test]
        public void MultipleInlineSignatureTest()
        {
            // Verify Inline Signature with multiple keys:
            // v6 key from crypto-refresh and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            // https://tests.sequoia-pgp.org/#Inline_Sign_with_minimal_key_from_RFC9760_and_key__Alice___verify_with_key_from_RFC9760

            // inline signed message generated by GopenPGP 3.0.0-alpha
            byte[] message = Base64.Decode(
                "xEYGAAobIPdza3bN03j7U7LE/Q/46kHCmsfVx2UmTPsNpUk/V/UWyxhsTwYJppfk" +
                "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkAxA0DAAoW8jFVDE9H444ByxRiAAAAAABI" +
                "ZWxsbyBXb3JsZCA6KcJ1BAAWCgAnBQJl4HbKCRDyMVUMT0fjjhYhBOuFu1+jOnXh" +
                "XpROY/IxVQxPR+OOAACKGAEAsQpg3dNdO4C9eMGn1jvVTjP0r2welMFD68dFU5d8" +
                "nq8A+gNFdJbX0PP0vNx/kIxpilbdssnF+a04CdVpAkwXmaYPwpgGABsKAAAAKQUC" +
                "ZeB2yiKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAACB3IPdz" +
                "a3bN03j7U7LE/Q/46kHCmsfVx2UmTPsNpUk/V/UWJsjxFqBQXqDFAaOjiv8oabeX" +
                "qvELkq1bKLb9fJ+ASfZW9FyI1ORHdCrI5zEnpfrFe4Id+xg9N39MTGq+OoPeDA==");

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleInlineSignaturesTest(message, bundle);

            // inline signed message generated by PGPy 0.6.0+dkg-crypto-refresh
            message = Base64.Decode(
                "xA0DAAoW8jFVDE9H444AxEYGAAobIFWUOmg2wsfVON4qIM1sWUPd9223ANjaMnHT" +
                "Mvad9EfVyxhsTwYJppfk1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkByxRiAGXgds5I" +
                "ZWxsbyBXb3JsZCA6KcKYBgAbCgAAACkFgmXgds4iIQbLGGxPBgmml+TVLfpscisM" +
                "Hx4nwYpWcI9lJewnutmsyQAAAACSWCBVlDpoNsLH1TjeKiDNbFlD3fdttwDY2jJx" +
                "0zL2nfRH1aouTY4WN/3DFsfP8yFg/BE7Ssaikt7bbXtBSH/AldOtyM1myiFsP+yx" +
                "8Img2A7eq9+wKTLjhPHl7zSh7y9KEATCdQQAFgoAHQWCZeB2zhYhBOuFu1+jOnXh" +
                "XpROY/IxVQxPR+OOAAoJEPIxVQxPR+OOgDcBAOz0kSpV4/F9Exxdq6oYlHZdsX5U" +
                "n9QpjmJVjo7bsMGDAQCd3PA5joXmfoKQhtQT5Qm1dhjfv/c89oPzdjQYmVLnCg==");

            VerifyMultipleInlineSignaturesTest(message, bundle);
        }

        [Test]
        public void GenerateAndVerifyMultipleInlineSignatureTest()
        {
            // Inline Sign-Verify roundtrip test with multiple keys:
            // v6 key from crypto-refresh and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] message;

            PgpSecretKey[] signingKeys = new PgpSecretKey[] {
                new PgpSecretKeyRing(v6UnlockedSecretKey).GetSecretKey(),
                new PgpSecretKeyRing(aliceSecretkey).GetSecretKey()
            };

            PgpSignatureGenerator[] generators = new PgpSignatureGenerator[] {
                CreateAndInitPgpSignatureGenerator(signingKeys[0], HashAlgorithmTag.Sha384, emptyPassphrase),
                CreateAndInitPgpSignatureGenerator(signingKeys[1], HashAlgorithmTag.Sha256, emptyPassphrase)
            };

            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bcOut = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    int sigCount  = generators.Length;
                    int count = 1;
                    foreach (PgpSignatureGenerator generator in generators)
                    {
                        generator.GenerateOnePassVersion(count != sigCount).Encode(bcOut);
                        count++;
                    }

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

                        foreach (PgpSignatureGenerator generator in generators)
                        {
                            generator.Update(data);
                        }
                    }

                    foreach (PgpSignatureGenerator generator in generators.Reverse())
                    {
                        generator.Generate().Encode(bcOut);
                    }
                }

                message = ms.ToArray();
            }

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleInlineSignaturesTest(message, bundle);

            //corrupt data;
            message[95] = 0x50;
            VerifyMultipleInlineSignaturesTest(message, bundle, shouldFail: true);
        }

        private void VerifyMultipleDetachedSignaturesTest(byte[] signaturePacket, byte[] data, PgpPublicKeyRingBundle bundle, bool shouldFail = false)
        {
            PgpObjectFactory factory = new PgpObjectFactory(signaturePacket);
            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;

            IsEquals(sigs.Count, 2);
            for (int i = 0; i < sigs.Count; i++)
            {
                PgpSignature sig = sigs[i];
                sig.InitVerify(bundle.GetPublicKey(sig.KeyId));
                sig.Update(data);

                IsTrue(shouldFail != sig.Verify());
            }
        }

        [Test]
        public void MultipleDetachedSignatureTest()
        {
            // Verify Detached Signature with multiple keys:
            // v6 key from crypto-refresh and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            // https://tests.sequoia-pgp.org/#Detached_Sign_with_minimal_key_from_RFC9760_and_key__Alice___verify_with_key_from_RFC9760

            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] corruptedData = Encoding.UTF8.GetBytes("Hello World :(");

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            // Detached Signature generated by GopenPGP 3.0.0-alpha
            byte[] signaturePacket = Base64.Decode(
                "wpgGABsKAAAAKQUCZeB2zCKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
                "2azJAAAAAEPPIIh5xfXDp5Zmfa7KJ0S+3Z+RBO9j5AC33ZRAwGgWKVuBts2H+I0k" +
                "GlIQXoyX+2LnurlGQGxZRqwk/z2d4Tk8oAA62CuJ318aZdo8Z4utdmHvsWlluAWl" +
                "lh0XdZ5l/qBNC8J1BAAWCgAnBQJl4HbMCRDyMVUMT0fjjhYhBOuFu1+jOnXhXpRO" +
                "Y/IxVQxPR+OOAABPnQEA881lXU6DUMYbXx3rmGa5qSQld9pHxzRYtBT/WCfkzVwA" +
                "/0/PN5jncrytAiEjb6YwuZuTVjJdTy6xtzuH+XALdREG");

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);

            // Detached Signature generated by PGPy 0.6.0+dkg-crypto-refresh
            signaturePacket = Base64.Decode(
                "wpgGABsKAAAAKQWCZeB20SIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
                "2azJAAAAADUkIIqFiPBBvz4Uqsug38k/hVaFdHoHfy82ESRfutwk1ch+TaG8Kk2I" +
                "7IMcrzKKSp60I7MEGb5CUCzeeM4v883yXlzZhwiBl+enR8kHxcVZzH+z7aS3OptN" +
                "mrcay8CfwzHJD8J1BAAWCgAdBYJl4HbRFiEE64W7X6M6deFelE5j8jFVDE9H444A" +
                "CgkQ8jFVDE9H447lbQEAx8hE9sbx1s8kMwuuEUtvoayJyz6R3PyQAIGH72g9XNcA" +
                "/32a6SYBHAHl8HOrlkZWzUwaIyhOcI5jN6ppiKRZAL8O");

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);
        }


        [Test]
        public void GenerateAndVerifyMultipleDetachedSignatureTest()
        {
            // Inline Sign-Verify roundtrip test with multiple keys:
            // v6 key from crypto-refresh and v4 key "Alice" from "OpenPGP Example Keys and Certificates"

            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] corruptedData = Encoding.UTF8.GetBytes("Hello World :(");
            byte[] signaturePacket;

            PgpSecretKey[] signingKeys = new PgpSecretKey[] {
                new PgpSecretKeyRing(v6UnlockedSecretKey).GetSecretKey(),
                new PgpSecretKeyRing(aliceSecretkey).GetSecretKey()
            };

            PgpSignatureGenerator[] generators = new PgpSignatureGenerator[] {
                CreateAndInitPgpSignatureGenerator(signingKeys[0], HashAlgorithmTag.Sha3_512, emptyPassphrase),
                CreateAndInitPgpSignatureGenerator(signingKeys[1], HashAlgorithmTag.Sha224, emptyPassphrase)
            };

            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bcOut = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    foreach (PgpSignatureGenerator generator in generators)
                    {
                        generator.Update(data);
                        generator.Generate().Encode(bcOut);
                    }
                }

                signaturePacket = ms.ToArray();
            }
            
            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);
        }

        [Test]
        public void Version5KeyParsingTest()
        {
            string uid = "emma.goldman@example.net";
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v5Certificate);
            PgpPublicKey[] pubKeys = pubRing.GetPublicKeys().ToArray();
            IsEquals("wrong number of public keys", pubKeys.Length, 2);

            PgpPublicKey masterKey = pubKeys[0];
            PgpPublicKey subKey = pubKeys[1];

            IsTrue(masterKey.IsMasterKey);
            IsTrue(subKey.IsEncryptionKey);
            IsEquals(masterKey.Algorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(subKey.Algorithm, PublicKeyAlgorithmTag.ECDH);

            IsTrue(masterKey.GetUserIds().Contains(uid));
            IsTrue(!masterKey.GetUserIds().Contains("emma.g@example.net"));

            IsEquals(masterKey.KeyId, 0x19347BC987246402);
            IsEquals((ulong)subKey.KeyId, 0xE4557C2B02FFBF4B);
            IsTrue(AreEqual(masterKey.GetFingerprint(), Hex.Decode("19347BC9872464025F99DF3EC2E0000ED9884892E1F7B3EA4C94009159569B54")));
            IsTrue(AreEqual(subKey.GetFingerprint(), Hex.Decode("E4557C2B02FFBF4B04F87401EC336AF7133D0F85BE7FD09BAEFD9CAEB8C93965")));

            // verify v5 self sig
            PgpSignature signature = masterKey.GetSignaturesForId(uid).ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version5);
            IsEquals(signature.SignatureType, PgpSignature.PositiveCertification);
            signature.InitVerify(masterKey);
            IsTrue(signature.VerifyCertification(uid, masterKey));

            // verify subkey binding sig
            signature = subKey.GetSignatures().ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version5);
            IsEquals(signature.SignatureType, PgpSignature.SubkeyBinding);
            signature.InitVerify(masterKey);
            IsTrue(signature.VerifyCertification(masterKey, subKey));
        }

        [Test]
        public void Version5InlineSignatureTest()
        {
            // Verify v5 Inline Signature generated by OpenPGP.js 5.5.0
            // https://tests.sequoia-pgp.org/#Inline_Sign-Verify_roundtrip_with_key__Emma_
            byte[] message = Base64.Decode(
                "xA0DAQoWGTR7yYckZAIByxR1AGXgdslIZWxsbyBXb3JsZCA6KcJ3BQEWCgAp" +
                "BQJl4HbJIiEFGTR7yYckZAJfmd8+wuAADtmISJLh97PqTJQAkVlWm1QAADsI" +
                "AQD7aH9a0GKcHdFThMsOQ88xAM5PiqPyDV1A/K23rPN28wD/QoPa1yEE3Y2R" +
                "ZtqtH6jAymdyIwtsa5wLvzUjTmP5OQo=");

            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v5Certificate);
            PgpPublicKey signer = pubRing.GetPublicKey();

            PgpObjectFactory factory = new PgpObjectFactory(message);

            PgpOnePassSignatureList opss = factory.NextPgpObject() as PgpOnePassSignatureList;
            IsEquals(opss.Count, 1);
            PgpOnePassSignature ops = opss[0];
            IsEquals(ops.Version, OnePassSignaturePacket.Version3);

            ops.InitVerify(signer);
            PgpLiteralData literal = factory.NextPgpObject() as PgpLiteralData;
            using (Stream dIn = literal.GetInputStream())
            {
                byte[] buffer = new byte[30];
                int bytesRead;
                while ((bytesRead = dIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ops.Update(buffer, 0, bytesRead);
                }
            }

            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;
            IsEquals(sigs.Count, 1);
            byte[] metadata = literal.GetMetadata(sigs[0].Version);
            IsTrue(ops.Verify(sigs[0], metadata));
        }


        public override string Name => "PgpInteroperabilityTestSuite";

        public override void PerformTest()
        {
            MultipleInlineSignatureTest();
            GenerateAndVerifyMultipleInlineSignatureTest();

            MultipleDetachedSignatureTest();
            GenerateAndVerifyMultipleDetachedSignatureTest();

            Version5KeyParsingTest();
            Version5InlineSignatureTest();
        }
    }
}
