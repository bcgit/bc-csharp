using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.OpenSsl.Tests
{
    /**
    * basic class for reading test.pem - the password is "secret"
    */
    [TestFixture]
    public class ReaderTest
        : SimpleTest
    {
        private readonly SecureRandom Random = new SecureRandom();

        public override string Name => "ReaderTest";

        [Test]
        public void TestGost3410_2012()
        {
            string data =
                "-----BEGIN PRIVATE KEY-----\n" +
                "MEMCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIIBidanaO5G6Go8A\n" +
                "thlDjR9rk4hij/PpjAQvXJr+zTqz\n" +
                "-----END PRIVATE KEY-----\n";

            using (var textReader = new StringReader(data))
            using (var pemReader = new PemReader(textReader))
            {
                var pemObj = pemReader.ReadPemObject();
                PrivateKeyFactory.CreateKey(pemObj.Content);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public override void PerformTest()
        {
            IPasswordFinder pGet = new TestPassword("secret");
            using (var pemRd = OpenPemResource("test.pem", pGet))
            {
                object o;
                while ((o = pemRd.ReadObject()) != null)
                {
                    //if (o is AsymmetricCipherKeyPair)
                    //{
                    //    ackp = (AsymmetricCipherKeyPair)o;

                    //    Console.WriteLine(ackp.Public);
                    //    Console.WriteLine(ackp.Private);
                    //}
                    //else
                    //{
                    //    Console.WriteLine(o.ToString());
                    //}
                }
            }

            // test bogus lines before begin are ignored.
            using (var pemRd = OpenPemResource("extratest.pem"))
            {
                object o;
                while ((o = pemRd.ReadObject()) != null)
                {
                    IsTrue("wrong object found", o is X509Certificate);
                }
            }

            //
            // pkcs 7 data
            //
            ContentInfo d;
            using (var pemRd = OpenPemResource("pkcs7.pem"))
            {
                d = (ContentInfo)pemRd.ReadObject();

                if (!d.ContentType.Equals(CmsObjectIdentifiers.EnvelopedData))
                {
                    Fail("failed envelopedData check");
                }
            }

            //
            // ECKey
            //
            using (var pemRd = OpenPemResource("eckey.pem"))
            {
                X962Parameters ecParams = (X962Parameters)pemRd.ReadObject();
                IsTrue(ecParams.IsNamedCurve);

                var dp = ECDomainParameters.FromX962Parameters(ecParams);
                IsTrue(dp != null);

                var ecKeyPair = (AsymmetricCipherKeyPair)pemRd.ReadObject();

                byte[] message = { (byte)'a', (byte)'b', (byte)'c' };

                var signer = SignerUtilities.InitSigner("ECDSA", forSigning: true, ecKeyPair.Private, Random);
                signer.BlockUpdate(message, 0, message.Length);
                byte[] signature = signer.GenerateSignature();

                var verifier = SignerUtilities.InitSigner("ECDSA", forSigning: false, ecKeyPair.Public, null);
                verifier.BlockUpdate(message, 0, message.Length);
                bool shouldVerify = verifier.VerifySignature(signature);

                IsTrue("EC verification failed", shouldVerify);

                // TODO Resolve this issue with the algorithm name, study Java version

                //if (!pair.getPublic().getAlgorithm().equals("ECDSA"))
                //{
                //    fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
                //}

                //if (!pair.getPrivate().getAlgorithm().equals("ECDSA"))
                //{
                //    fail("wrong algorithm name on private");
                //}

                ////
                //// Check for algorithm replacement
                ////
                //pair = new JcaPEMKeyConverter().setProvider("BC").setAlgorithmMapping(X9ObjectIdentifiers.id_ecPublicKey, "EC").getKeyPair(pemPair);

                //if (!pair.getPublic().getAlgorithm().equals("EC"))
                //{
                //    fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
                //}

                //if (!pair.getPrivate().getAlgorithm().equals("EC"))
                //{
                //    fail("wrong algorithm name on private");
                //}
            }

            //
            // ECKey -- explicit parameters
            //
            using (var pemRd = OpenPemResource("ecexpparam.pem"))
            {
                X962Parameters ecParams = (X962Parameters)pemRd.ReadObject();
                IsTrue(!ecParams.IsNamedCurve && !ecParams.IsImplicitlyCA);

                var dp = ECDomainParameters.FromX962Parameters(ecParams);
                IsTrue(dp != null);

                var ecKeyPair = (AsymmetricCipherKeyPair)pemRd.ReadObject();

                byte[] message = { (byte)'a', (byte)'b', (byte)'c' };

                var signer = SignerUtilities.InitSigner("ECDSA", forSigning: true, ecKeyPair.Private, Random);
                signer.BlockUpdate(message, 0, message.Length);
                byte[] signature = signer.GenerateSignature();

                var verifier = SignerUtilities.InitSigner("ECDSA", forSigning: false, ecKeyPair.Public, null);
                verifier.BlockUpdate(message, 0, message.Length);
                bool shouldVerify = verifier.VerifySignature(signature);

                IsTrue("EC verification failed", shouldVerify);

                // TODO Resolve this issue with the algorithm name, study Java version

                //if (!pair.getPublic().getAlgorithm().equals("ECDSA"))
                //{
                //    fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
                //}

                //if (!pair.getPrivate().getAlgorithm().equals("ECDSA"))
                //{
                //    fail("wrong algorithm name on private");
                //}
            }

            //
            // writer/parser test
            //
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 768, 25));

            var kp = kpGen.GenerateKeyPair();

            ImplKeyPairTest("RSA", kp);

            //kpGen = KeyPairGenerator.getInstance("DSA");
            //kpGen.initialize(512, Random);
            DsaParametersGenerator pGen = new DsaParametersGenerator();
            pGen.Init(512, 80, Random);

            kpGen = GeneratorUtilities.GetKeyPairGenerator("DSA");
            kpGen.Init(new DsaKeyGenerationParameters(Random, pGen.GenerateParameters()));

            kp = kpGen.GenerateKeyPair();

            ImplKeyPairTest("DSA", kp);

            //
            // PKCS7
            //
            MemoryStream bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(d);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                d = (ContentInfo)pemRd.ReadObject();

                if (!CmsObjectIdentifiers.EnvelopedData.Equals(d.ContentType))
                {
                    Fail("failed EnvelopedData recode check");
                }
            }

            // OpenSSL test cases (as embedded resources)
            ImplOpenSslDsaTest("unencrypted");
            ImplOpenSslRsaTest("unencrypted");

            ImplOpenSslTests("aes128");
            ImplOpenSslTests("aes192");
            ImplOpenSslTests("aes256");
            ImplOpenSslTests("blowfish");
            ImplOpenSslTests("des1");
            ImplOpenSslTests("des2");
            ImplOpenSslTests("des3");
            ImplOpenSslTests("rc2_128");

            ImplOpenSslDsaTest("rc2_40_cbc");
            ImplOpenSslRsaTest("rc2_40_cbc");
            ImplOpenSslDsaTest("rc2_64_cbc");
            ImplOpenSslRsaTest("rc2_64_cbc");

            ImplDudPasswordTest("7fd98", 0, "corrupted stream - out of bounds length found: 599005160 > 19");
            ImplDudPasswordTest("ef677", 1, "corrupted stream - out of bounds length found: 2087569732 > 66");
            ImplDudPasswordTest("800ce", 2, "unknown tag 26 encountered");
            ImplDudPasswordTest("b6cd8", 3, "DEF length 81 object truncated by 56");
            ImplDudPasswordTest("28ce09", 4, "corrupted stream - high tag number < 31 found");
            ImplDudPasswordTest("2ac3b9", 5, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("2cba96", 6, "corrupted stream - out of bounds length found: 100 > 67");
            ImplDudPasswordTest("2e3354", 7, "corrupted stream - out of bounds length found: 42 > 35");
            ImplDudPasswordTest("2f4142", 8, "corrupted stream - out of bounds length found: 127 > 39");
            ImplDudPasswordTest("2fe9bb", 9, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("3ee7a8", 10, "long form definite-length more than 31 bits");
            ImplDudPasswordTest("41af75", 11, "unknown tag 16 encountered");
            ImplDudPasswordTest("1704a5", 12, "BOOLEAN value should have 1 byte in it");
            ImplDudPasswordTest("1c5822", 13, "extra data found after object");
            ImplDudPasswordTest("5a3d16", 14, "truncated BIT STRING detected");
            ImplDudPasswordTest("8d0c97", 15, "too few objects in input sequence");
            ImplDudPasswordTest("bc0daf", 16, "BOOLEAN value should have 1 byte in it");
            ImplDudPasswordTest("aaf9c4d", 17, "unknown DL object encountered: 0x15");

            ImplNoPasswordTest();
            //ImplNoECPublicKeyTest();

            // encrypted private key test
            pGet = new TestPassword("password");
            using (var pemRd = OpenPemResource("enckey.pem", pGet))
            {
                var privKey = (RsaPrivateCrtKeyParameters)pemRd.ReadObject();

                if (!privKey.PublicExponent.Equals(new BigInteger("10001", 16)))
                {
                    Fail("decryption of private key data check failed");
                }
            }

            // general PKCS8 test
            using (var pemRd = OpenPemResource("pkcs8test.pem", pGet))
            {
                RsaPrivateCrtKeyParameters privKey;
                while ((privKey = (RsaPrivateCrtKeyParameters)pemRd.ReadObject()) != null)
                {
                    if (!privKey.PublicExponent.Equals(new BigInteger("10001", 16)))
                    {
                        Fail("decryption of private key data check failed");
                    }
                }
            }

            using (var pemRd = OpenPemResource("trusted_cert.pem"))
            {
                X509TrustedCertificateBlock trusted = (X509TrustedCertificateBlock)pemRd.ReadObject();

                CheckTrustedCert(trusted);

                MemoryStream trustedBuf = new MemoryStream();
                using (var trustedWriter = new PemWriter(new StreamWriter(trustedBuf)))
                {
                    trustedWriter.WriteObject(trusted);
                }

                var trustedEncoding = trustedBuf.ToArray();

                using (var trustedReader = new PemReader(new StreamReader(new MemoryStream(trustedEncoding, false))))
                {
                    trusted = (X509TrustedCertificateBlock)trustedReader.ReadObject();
                }

                CheckTrustedCert(trusted);
            }

            //
            // EdDSAKey
            //
            using (var pemRd = OpenPemResource("eddsapriv.pem"))
            {
                Ed25519PrivateKeyParameters edPrivKey = (Ed25519PrivateKeyParameters)pemRd.ReadObject();
                Ed25519PublicKeyParameters edPubKey = edPrivKey.GeneratePublicKey();

                byte[] msg = Strings.ToByteArray("Hello, world!");

                Ed25519Signer edSig = new Ed25519Signer();
                edSig.Init(forSigning: true, edPrivKey);
                edSig.BlockUpdate(msg, 0, msg.Length);
                byte[] s = edSig.GenerateSignature();

                edSig.Init(forSigning: false, edPubKey);
                edSig.BlockUpdate(msg, 0, msg.Length);
                Assert.True(edSig.VerifySignature(s));
            }

            ImplOpenSslGost2012Test();
            //ImplParseAttrECKeyTest();
        }

        private void CheckTrustedCert(X509TrustedCertificateBlock trusted)
        {
            CertificateTrustBlock trustBlock = trusted.TrustBlock;

            Assert.AreEqual("Fred", trustBlock.GetAlias(), "alias not found");
            Assert.AreEqual(3, trustBlock.GetUses().Count, "key purpose usages wrong size");
            Assert.That(trustBlock.GetUses().Contains(KeyPurposeID.id_kp_OCSPSigning), "key purpose use not found");
            Assert.AreEqual(1, trustBlock.GetProhibitions().Count, "key purpose prohibitions wrong size");
            Assert.That(trustBlock.GetProhibitions().Contains(KeyPurposeID.id_kp_clientAuth),
                "key purpose prohibition not found");
        }

        private void ImplKeyPairTest(string name, AsymmetricCipherKeyPair pair)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(pair.Public);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                AsymmetricKeyParameter pubK = (AsymmetricKeyParameter)pemRd.ReadObject();
                if (!pubK.Equals(pair.Public))
                {
                    Fail("Failed public key read: " + name);
                }
            }

            bOut = new MemoryStream();
            using (var pWrt = new PemWriter(new StreamWriter(bOut)))
            {
                pWrt.WriteObject(pair.Private);
            }

            using (var pemRd = new PemReader(new StreamReader(new MemoryStream(bOut.ToArray(), false))))
            {
                AsymmetricCipherKeyPair kPair = (AsymmetricCipherKeyPair)pemRd.ReadObject();
                if (!kPair.Private.Equals(pair.Private))
                {
                    Fail("Failed private key read: " + name);
                }
                if (!kPair.Public.Equals(pair.Public))
                {
                    Fail("Failed private key public read: " + name);
                }
            }
        }

        private void ImplOpenSslTests(string baseName)
        {
            ImplOpenSslDsaModesTest(baseName);
            ImplOpenSslRsaModesTest(baseName);
        }

        private void ImplOpenSslDsaModesTest(string baseName)
        {
            ImplOpenSslDsaTest(baseName + "_cbc");
            ImplOpenSslDsaTest(baseName + "_cfb");
            ImplOpenSslDsaTest(baseName + "_ecb");
            ImplOpenSslDsaTest(baseName + "_ofb");
        }

        private void ImplOpenSslRsaModesTest(string baseName)
        {
            ImplOpenSslRsaTest(baseName + "_cbc");
            ImplOpenSslRsaTest(baseName + "_cfb");
            ImplOpenSslRsaTest(baseName + "_ecb");
            ImplOpenSslRsaTest(baseName + "_ofb");
        }

        private void ImplOpenSslDsaTest(string name)
        {
            string fileName = "dsa.openssl_dsa_" + name + ".pem";

            ImplOpenSslTestFile(fileName, typeof(DsaPrivateKeyParameters));
        }

        private void ImplOpenSslGost2012Test()
        {
            // check for algorithm
            Assert.NotNull(GeneratorUtilities.GetKeyPairGenerator("ECGOST3410-2012"));

            //string privFile = "data/gost2012_priv.pem";
            string privFile = "gost2012_priv.pem";

            ECPrivateKeyParameters privKey;
            using (var privReader = OpenPemResource(privFile, new TestPassword("test")))
            {
                privKey = (ECPrivateKeyParameters)privReader.ReadObject();
            }

            //string certFile = "data/gost2012_cert.pem";
            string certFile = "gost2012_cert.pem";

            X509Certificate cert;
            ECPublicKeyParameters pubKey;
            using (var certReader = OpenPemResource(certFile))
            {
                cert = (X509Certificate)certReader.ReadObject();
                pubKey = (ECPublicKeyParameters)cert.GetPublicKey();

                cert.Verify(pubKey);
            }

            // Confirm interop of private and public keys
            var signatureFactory = new Asn1SignatureFactory(cert.SignatureAlgorithm, privKey);
            DerBitString signature = X509.X509Utilities.GenerateSignature(signatureFactory, cert.TbsCertificate);

            var verifierFactory = new Asn1VerifierFactoryProvider(pubKey).CreateVerifierFactory(cert.SignatureAlgorithm);
            bool shouldVerify = X509.X509Utilities.VerifySignature(verifierFactory, cert.TbsCertificate, signature);
            Assert.True(shouldVerify);
        }

        private void ImplOpenSslRsaTest(string name)
        {
            string fileName = "rsa.openssl_rsa_" + name + ".pem";

            ImplOpenSslTestFile(fileName, typeof(RsaPrivateCrtKeyParameters));
        }

        private void ImplOpenSslTestFile(string fileName, Type expectedPrivKeyType)
        {
            using (var pr = OpenPemResource(fileName, new TestPassword("changeit")))
            {
                AsymmetricCipherKeyPair kp = pr.ReadObject() as AsymmetricCipherKeyPair;

                if (kp == null)
                {
                    Fail("Didn't find OpenSSL key");
                }

                if (!expectedPrivKeyType.IsInstanceOfType(kp.Private))
                {
                    Fail("Returned key not of correct type");
                }
            }
        }

        private void ImplDudPasswordTest(string password, int index, string message)
        {
            // illegal state exception check - in this case the wrong password will
            // cause an underlying class cast exception.
            try
            {
                IPasswordFinder pGet = new TestPassword(password);
                using (var pemRd = OpenPemResource("test.pem", pGet))
                {
                    object o;
                    while ((o = pemRd.ReadObject()) != null)
                    {
                    }
                }
                Fail("issue not detected: " + index);
            }
            catch (Exception e)
            {
                var uc = e;
                while (uc.InnerException != null)
                {
                    uc = uc.InnerException;
                }

                // "StartsWith" because the parameter name will often be appended
                if (!uc.Message.StartsWith(message))
                {
                    Fail("issue " + index + " exception thrown, but wrong message: " + uc.Message + " expected: " + message);
                }
            }
        }

        private void ImplNoPasswordTest()
        {
            bool foundAny = false;
            using (var pemRd = OpenPemResource("smimenopw.pem"))
            {
                object o;
                while ((o = pemRd.ReadObject()) != null)
                {
                    IsTrue(o is AsymmetricKeyParameter key && key.IsPrivate);
                    foundAny = true;
                }
            }
            IsTrue("private key not detected", foundAny);
        }

        //private void ImplNoECPublicKeyTest()
        //{
        //    /*
        //     * This was apparently intended as EC private key without the public key defined, but it is an invalid
        //     * encoding, which bc-java does not detect because it simply stores the sequence without parsing.
        //     */
        //    string ecSample =
        //        "-----BEGIN EC PRIVATE KEY-----\n" +
        //        "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgvYiiubZYNO1WXXi3\n" +
        //        "jmGT9DLeFemvlmR1zTA0FdcSAG2gCgYIKoZIzj0DAQehRANCAATNXYa06ykwhxuy\n" +
        //        "Dg+q6zsVqOLk9LtXz/1fzf9AkAVm9lBMTZAh+FRfregBgl08LATztGlTh/z0dPnp\n" +
        //        "dW2jFrDn\n" +
        //        "-----END EC PRIVATE KEY-----\n";

        //    using (var textReader = new StringReader(ecSample))
        //    using (var pemReader = new PemReader(textReader))
        //    {
        //        var ecKeyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

        //        // Unlike bc-java, PemReader should reconstruct the EC public key automatically
        //        IsTrue(ecKeyPair != null);
        //    }
        //}

        // Parsing of the PEM contents fails, apparently due to an invalid DerExternal (failing a type constraint that
        // bc-java doesn't check for). It seems unlikely that the ASN.1 is valid.
        //private void ImplParseAttrECKeyTest()
        //{
        //    // EC private key extremely dodgy attributes.
        //    using (var pemRd = OpenPemResource("ec_attr_key.pem"))
        //    {
        //        var ecKeyPair = (AsymmetricCipherKeyPair)pemRd.ReadObject();

        //        // Unlike bc-java, PemReader should reconstruct the EC public key automatically
        //        IsTrue(ecKeyPair != null);
        //    }
        //}

        private static PemReader OpenPemResource(string fileName, IPasswordFinder pGet = null)
        {
            Stream data = GetTestDataAsStream("openssl." + fileName);
            TextReader tr = new StreamReader(data);
            return new PemReader(tr, pGet);
        }
    }
}
