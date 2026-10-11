using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    /// <summary>
    /// CMS SignedData and PKIX certification path validation for the Composite ML-DSA combinations
    /// (draft-ietf-lamps-pq-composite-sigs).
    /// </summary>
    [TestFixture]
    public class CompositeMLDsaSignedDataTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly IEnumerable<string> Names = CompositeMLDsaParameters.ByName.Keys;

        private IDictionary<string, CompositeMLDsaPrivateKeyParameters> m_vectorKeys;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_vectorKeys = new Dictionary<string, CompositeMLDsaPrivateKeyParameters>();
            foreach (var testVector in CompositeMLDsaTest.LoadTestVectors(out _))
            {
                string name = testVector["tcId"].Substring("id-".Length);
                if (CompositeMLDsaParameters.ByName.TryGetValue(name, out var parameters))
                {
                    m_vectorKeys.Add(name,
                        CompositeMLDsaPrivateKeyParameters.FromEncoding(parameters, Base64.Decode(testVector["sk"])));
                }
            }
        }

        // TODO[cms] Port bc-java's testCompositeMLDSASignedData once CMS SignedData supports Composite ML-DSA
        //[TestCaseSource(nameof(Names))]
        //public void TestCompositeMLDsaSignedData(string name)
        //{
        //}

        [TestCaseSource(nameof(Names))]
        public void TestCompositeMLDsaCertPath(string name)
        {
            var validator = new PkixCertPathValidator();

            GetKeyPairs(name, out var caKp, out var eeKp);

            var caDN = new X509Name("CN=Composite CA " + name);
            var caCert = BuildCert(caDN, caKp.Private, name, caDN, caKp.Public, ca: true, 1);

            var eeCert = BuildCert(caDN, caKp.Private, name, new X509Name("CN=Composite EE " + name), eeKp.Public,
                ca: false, 2);

            var trust = new HashSet<TrustAnchor>{ new TrustAnchor(caCert, null) };

            var certPath = new PkixCertPath(new List<X509Certificate>{ eeCert });
            var pkixParams = new PkixParameters(trust);
            pkixParams.IsRevocationEnabled = false;
            validator.Validate(certPath, pkixParams);

            // Negative control: an EE certificate signed by a key outside the anchor must not validate.
            var rogueEE = BuildCert(caDN, eeKp.Private, name, new X509Name("CN=Rogue EE " + name), eeKp.Public,
                ca: false, 3);
            var badCertPath = new PkixCertPath(new List<X509Certificate>{ rogueEE });
            var e = Assert.Throws<PkixCertPathValidatorException>(() => validator.Validate(badCertPath, pkixParams),
                name + ": CertPath validated an EE signed by a key outside the anchor");
            Assert.AreEqual(PkixCertPathValidatorReason.InvalidSignature, e.Reason, name + ": rejection reason");
        }

        private static X509Certificate BuildCert(X509Name issuer, AsymmetricKeyParameter issuerKey, string sigName,
            X509Name subject, AsymmetricKeyParameter subjectKey, bool ca, long serial)
        {
            DateTime now = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.ValueOf(serial));
            certGen.SetIssuerDN(issuer);
            certGen.SetSubjectDN(subject);
            certGen.SetNotBefore(now.AddHours(-1));
            certGen.SetNotAfter(now.AddDays(365));
            certGen.SetPublicKey(subjectKey);

            certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(ca));
            certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                new KeyUsage(ca ? (KeyUsage.KeyCertSign | KeyUsage.DigitalSignature) : KeyUsage.DigitalSignature));

            return certGen.Generate(new Asn1SignatureFactory(sigName, issuerKey, Random));
        }

        /// <summary>Two distinct key pairs for the combination.</summary>
        private void GetKeyPairs(string name, out AsymmetricCipherKeyPair kp0, out AsymmetricCipherKeyPair kp1)
        {
            var parameters = CompositeMLDsaParameters.ByName[name];
            if (parameters.KeyType != CompositeMLDsaParameters.TraditionalKeyType.Rsa)
            {
                kp0 = GenerateKeyPair(name);
                kp1 = GenerateKeyPair(name);
                return;
            }

            /*
             * RSA key generation takes seconds, so the first key comes from the test vectors, and the second pairs a
             * fresh ML-DSA seed with the RSA key from another vector of the same size.
             */
            // TODO Review the source of these test keys
            var vectorKey = m_vectorKeys[name];
            var otherRsaKey = CollectionUtilities.GetFirstOrNull(CollectionUtilities.Where(m_vectorKeys.Values,
                key => key != vectorKey
                    && key.Parameters.KeyType == CompositeMLDsaParameters.TraditionalKeyType.Rsa
                    && key.Parameters.RsaKeySize == parameters.RsaKeySize)).TraditionalPrivateKey;

            byte[] seed = new byte[parameters.MLDsaSeedLength];
            Random.NextBytes(seed);
            var otherKey = new CompositeMLDsaPrivateKeyParameters(parameters,
                MLDsaPrivateKeyParameters.FromSeed(parameters.MLDsaParameters, seed), otherRsaKey);

            kp0 = new AsymmetricCipherKeyPair(vectorKey.GetPublicKey(), vectorKey);
            kp1 = new AsymmetricCipherKeyPair(otherKey.GetPublicKey(), otherKey);
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(string name)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(name);
            generator.Init(new KeyGenerationParameters(Random, 0));
            return generator.GenerateKeyPair();
        }
    }
}
