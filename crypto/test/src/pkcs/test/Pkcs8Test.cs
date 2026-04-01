using System;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

// Use aliases to avoid ambiguity between BC and .NET X509 types
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace Org.BouncyCastle.Pkcs.Tests
{
    [TestFixture]
    public class Pkcs8Test
    {
        [Test]
        public void TestRsaPublicKeyInfoEncodingHasNullParameters()
        {
            // Generate a small RSA key for testing
            RsaKeyPairGenerator pGen = new RsaKeyPairGenerator();
            pGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();
            RsaKeyParameters pubKey = (RsaKeyParameters)pair.Public;

            // Encode to SubjectPublicKeyInfo (PKCS#8 / X.509 format)
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            byte[] encoded = info.GetEncoded(Asn1Encodable.Der);

            // The AlgorithmIdentifier for RSA (1.2.840.113549.1.1.1) MUST include DER NULL (05 00)
            // in its parameters field according to RFC 8017 / PKCS#1 v2.2.
            
            string hexEncoded = Hex.ToHexString(encoded).ToLowerInvariant();
            
            // OID for rsaEncryption: 06 09 2a 86 48 86 f7 0d 01 01 01
            // Followed by NULL: 05 00
            string expectedSequence = "06092a864886f70d0101010500";
            
            Assert.IsTrue(hexEncoded.Contains(expectedSequence), 
                "RSA AlgorithmIdentifier in SubjectPublicKeyInfo missing mandatory NULL parameters (05 00).");
        }

        [Test]
        public void TestDotNetUtilitiesGetSubjectPublicKeyInfoDer()
        {
#if NETCOREAPP1_0_OR_GREATER || NETSTANDARD1_1_OR_GREATER || NET471_OR_GREATER
            // Generate RSA key
            RsaKeyPairGenerator pGen = new RsaKeyPairGenerator();
            pGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();

            // Generate a self-signed certificate using BC
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(new X509Name("CN=Test Issuer"));
            certGen.SetSubjectDN(new X509Name("CN=Test Subject"));
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            certGen.SetPublicKey(pair.Public);

            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", pair.Private);
            BcX509Certificate bcCert = certGen.Generate(signatureFactory);

            // Convert to .NET X509Certificate2
            var dotNetCert = new SystemX509.X509Certificate2(bcCert.GetEncoded());

            // Use the new utility method
            byte[] encoded = DotNetUtilities.GetSubjectPublicKeyInfoDer(dotNetCert);

            // Verify logic: RSA encoded SubjectPublicKeyInfo must have the correct structure
            string hexEncoded = Hex.ToHexString(encoded).ToLowerInvariant();
            string expectedOidAndNull = "06092a864886f70d0101010500";
            
            Assert.IsTrue(hexEncoded.Contains(expectedOidAndNull), 
                "DotNetUtilities.GetSubjectPublicKeyInfoDer failed to produce correct RSA encoding with NULL parameters.");
#endif
        }

        [Test]
        public void TestSubjectPublicKeyInfoFactoryConsistency()
        {
            // Verify that SubjectPublicKeyInfoFactory produces consistent results for RSA
            RsaKeyPairGenerator pGen = new RsaKeyPairGenerator();
            pGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            AsymmetricCipherKeyPair pair = pGen.GenerateKeyPair();
            
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public);
            AlgorithmIdentifier algId = info.AlgorithmID;
            
            Assert.AreEqual(PkcsObjectIdentifiers.RsaEncryption, algId.Algorithm);
            Assert.IsInstanceOf<DerNull>(algId.Parameters, "RSA AlgorithmIdentifier parameters should be DerNull.");
        }
    }
}
