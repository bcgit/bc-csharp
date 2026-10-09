using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp.Tests
{
    /// <summary>
    /// The hash used for the certHash of a certConf (RFC 9810 5.3.18): the one the certificate's signature algorithm
    /// specifies, or the one specified for hashing certificates signed with it, or else the one named in hashAlg.
    /// </summary>
    [TestFixture]
    public class CertHashTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static IEnumerable<TestCaseData> DerivedHashCases()
        {
            // Specified by the signature algorithm, through the digest algorithm finder.
            yield return Case("ECDSA", "SHA384withECDSA", "EC",
                new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random), NistObjectIdentifiers.IdSha384);

            // RFC 9481 3.3: specified for hashing certificates signed with EdDSA.
            yield return Case("Ed25519", "Ed25519", "Ed25519", new KeyGenerationParameters(Random, 0),
                NistObjectIdentifiers.IdSha512);
            yield return Case("Ed448", "Ed448", "Ed448", new KeyGenerationParameters(Random, 0),
                NistObjectIdentifiers.IdShake256);

            // The pre-hash variants of ML-DSA and SLH-DSA name their hash.
            yield return Case("HashML-DSA", "ML-DSA-65-WITH-SHA512", "ML-DSA",
                new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_65_with_sha512),
                NistObjectIdentifiers.IdSha512);
            yield return Case("HashSLH-DSA SHA2", "SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA",
                new SlhDsaKeyGenerationParameters(Random, SlhDsaParameters.slh_dsa_sha2_128f_with_sha256),
                NistObjectIdentifiers.IdSha256);
            yield return Case("HashSLH-DSA SHAKE", "SLH-DSA-SHAKE-128F-WITH-SHAKE128", "SLH-DSA",
                new SlhDsaKeyGenerationParameters(Random, SlhDsaParameters.slh_dsa_shake_128f_with_shake128),
                NistObjectIdentifiers.IdShake128);
        }

        private static IEnumerable<TestCaseData> HashAlgRequiredCases()
        {
            // The pure variants of ML-DSA and SLH-DSA specify no hash, and none is specified for them.
            yield return Case("ML-DSA", "ML-DSA-44", "ML-DSA",
                new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_44));
            yield return Case("SLH-DSA", "SLH-DSA-SHA2-128F", "SLH-DSA",
                new SlhDsaKeyGenerationParameters(Random, SlhDsaParameters.slh_dsa_sha2_128f));
        }

        [TestCaseSource(nameof(DerivedHashCases))]
        public void TestDerivedCertHash(string algorithm, string keyAlgorithm, KeyGenerationParameters keyGenParameters,
            DerObjectIdentifier expectedDigestOid)
        {
            var certificate = MakeCertificate(algorithm, keyAlgorithm, keyGenParameters);

            var content = new CertificateConfirmationContentBuilder()
                .AddAcceptedCertificate(certificate, BigInteger.One)
                .Build();

            var certStatus = content.ToAsn1Structure().ToCertStatusArray()[0];
            Assert.IsNull(certStatus.HashAlg, "hashAlg is only for when the hash cannot be derived");
            Assert.True(Arrays.AreEqual(DigestUtilities.CalculateDigest(expectedDigestOid, certificate.GetEncoded()),
                certStatus.CertHash.GetOctets()), "certHash");

            Assert.True(content.GetStatusMessages()[0].IsVerified(certificate), "certHash verifies");
        }

        [TestCaseSource(nameof(HashAlgRequiredCases))]
        public void TestHashAlgRequired(string algorithm, string keyAlgorithm, KeyGenerationParameters keyGenParameters)
        {
            var certificate = MakeCertificate(algorithm, keyAlgorithm, keyGenParameters);
            byte[] encoding = certificate.GetEncoded();

            // Without a hash to derive, the confirmation cannot be built without naming one.
            var builder = new CertificateConfirmationContentBuilder()
                .AddAcceptedCertificate(certificate, BigInteger.One);
            Assert.Throws<CmpException>(() => builder.Build());

            // A received confirmation naming its hash in hashAlg is checked with that hash.
            var hashAlg = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);
            byte[] certHash = DigestUtilities.CalculateDigest(hashAlg.Algorithm, encoding);
            Assert.True(ReceiveStatus(certHash, hashAlg).IsVerified(certificate), "certHash with hashAlg");

            byte[] otherHash = DigestUtilities.CalculateDigest(NistObjectIdentifiers.IdSha512, encoding);
            Assert.False(ReceiveStatus(otherHash, hashAlg).IsVerified(certificate), "certHash not matching hashAlg");

            // One without hashAlg cannot be checked at all.
            var status = ReceiveStatus(certHash, null);
            Assert.Throws<CmpException>(() => status.IsVerified(certificate));
        }

        [Test]
        public void TestHashAlgOverridesDerivedHash()
        {
            // hashAlg, when present, names the hash used, even where one could have been derived.
            var certificate = MakeCertificate("Ed25519", "Ed25519", new KeyGenerationParameters(Random, 0));
            var hashAlg = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);
            byte[] certHash = DigestUtilities.CalculateDigest(hashAlg.Algorithm, certificate.GetEncoded());

            Assert.True(ReceiveStatus(certHash, hashAlg).IsVerified(certificate), "certHash with hashAlg");
            Assert.False(ReceiveStatus(certHash, null).IsVerified(certificate), "certHash with the derived hash");
        }

        private static TestCaseData Case(string label, params object[] args) =>
            new TestCaseData(args).SetArgDisplayNames(label);

        private static X509Certificate MakeCertificate(string algorithm, string keyAlgorithm,
            KeyGenerationParameters keyGenParameters)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(keyAlgorithm);
            generator.Init(keyGenParameters);
            var keyPair = generator.GenerateKeyPair();

            var name = new X509Name("CN=" + algorithm);
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(now.AddMinutes(-5));
            certGen.SetNotAfter(now.AddHours(1));
            certGen.SetPublicKey(keyPair.Public);

            return certGen.Generate(new Asn1SignatureFactory(algorithm, keyPair.Private, Random));
        }

        /// <summary>A CertStatus as a CA would receive it in a certConf.</summary>
        private static CertificateStatus ReceiveStatus(byte[] certHash, AlgorithmIdentifier hashAlg)
        {
            var certStatus = new CertStatus(certHash, BigInteger.One, null, hashAlg);
            var received = CertConfirmContent.GetInstance(
                Asn1Object.FromByteArray(new DerSequence(certStatus).GetEncoded()));
            return new CertificateConfirmationContent(received).GetStatusMessages()[0];
        }
    }
}
