using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp.Tests
{
    /// <summary>
    /// CMP certificate enrolment with Composite ML-DSA keys, through public, algorithm-agnostic API only.
    /// </summary>
    /// <remarks>
    /// Beyond naming the combinations, nothing here names a Composite ML-DSA type: keys are held as
    /// <see cref="AsymmetricKeyParameter"/> and algorithms are chosen by name. The keys are the published test vector
    /// keys, so the test is fast and deterministic.
    /// </remarks>
    [TestFixture]
    public class CompositeMLDsaCmpTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly char[] SharedSecret = "composite enrolment secret".ToCharArray();

        private static readonly IList<string> Names = new List<string>(CompositeMLDsaParameters.ByName.Keys);

        private IDictionary<string, AsymmetricCipherKeyPair> m_vectorKeys;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            m_vectorKeys = new Dictionary<string, AsymmetricCipherKeyPair>();
            foreach (var testVector in CompositeMLDsaTest.LoadTestVectors(out _))
            {
                string name = testVector["tcId"].Substring("id-".Length);
                if (!CompositeMLDsaParameters.ByName.ContainsKey(name))
                    continue;

                var privateKey = PrivateKeyFactory.CreateKey(Base64.Decode(testVector["sk_pkcs8"]));
                var publicKey = new X509CertificateParser().ReadCertificate(Base64.Decode(testVector["x5c"]))
                    .GetPublicKey();

                m_vectorKeys.Add(name, new AsymmetricCipherKeyPair(publicKey, privateKey));
            }

            Assert.AreEqual(Names.Count, m_vectorKeys.Count, "test vector keys");
        }

        /// <summary>
        /// Initial registration (ir/ip/certConf/pkiConf) with each combination as the CA, enrolling a subject
        /// holding the next combination's key, so that every combination also appears once as a subject.
        /// </summary>
        /// <remarks>
        /// As usual for initial registration, the subject authenticates its messages with a shared secret (PBM);
        /// the composite signatures are the subject's proof of possession and the CA's message protection.
        /// </remarks>
        [TestCaseSource(nameof(Names))]
        public void TestInitialRegistration(string caAlgorithm)
        {
            string subjectAlgorithm = Names[(Names.IndexOf(caAlgorithm) + 1) % Names.Count];

            var ca = new CA(caAlgorithm, m_vectorKeys[caAlgorithm]);
            var subjectKeys = m_vectorKeys[subjectAlgorithm];
            var subjectDN = new X509Name("CN=" + subjectAlgorithm + " Subject,O=Bouncy Castle");
            var subjectName = new GeneralName(subjectDN);
            byte[] transactionID = SecureRandom.GetNextBytes(Random, 16);

            // 1. Subject: ir, with a signature proof of possession made with the key being certified.
            var requestBuilder = new CertificateReqMessagesBuilder();
            requestBuilder.AddRequest(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(subjectDN)
                .SetPublicKey(subjectKeys.Public)
                .SetProofOfPossessionSignKeySigner(
                    new Asn1SignatureFactory(subjectAlgorithm, subjectKeys.Private, Random))
                .Build());

            var ir = RoundTrip(new ProtectedPkiMessageBuilder(subjectName, ca.Name)
                .SetTransactionId(transactionID)
                .SetBody(PkiBody.TYPE_INIT_REQ, requestBuilder.Build())
                .Build(new PKMacBuilder().Build(SharedSecret)));

            // 2. CA: authenticate the ir, check the proof of possession, and issue from the template.
            Assert.True(ir.HasPasswordBasedMacProtected, subjectAlgorithm + ": ir protection type");
            Assert.True(ir.Verify(new PKMacBuilder(), SharedSecret), subjectAlgorithm + ": ir protection");
            Assert.AreEqual(PkiBody.TYPE_INIT_REQ, ir.Body.Type);

            var request = CertificateReqMessages.FromPkiBody(ir.Body).GetRequests()[0];
            var issued = ca.Issue(CheckSigningKeyPop(subjectAlgorithm, request));

            var response = new CertificateResponseBuilder(request.GetCertReqID(),
                new PkiStatusInfo(PkiStatusEncodable.granted)).WithCertificate(issued).Build();

            var ip = RoundTrip(ca.Protect(new ProtectedPkiMessageBuilder(ca.Name, subjectName)
                .SetTransactionId(transactionID)
                .SetBody(PkiBody.TYPE_INIT_REP, new CertificateRepMessageBuilder(ca.Certificate)
                    .AddCertificateResponse(response)
                    .Build())));

            // 3. Subject: check the CA's protection, then take the certificate.
            var certificate = CheckCertificateResponse(ca, ip, PkiBody.TYPE_INIT_REP, subjectKeys.Public);

            // 4. Subject: certConf, whose certHash uses the hash of the certificate's signature algorithm.
            var confirmation = new CertificateConfirmationContentBuilder()
                .AddAcceptedCertificate(certificate, BigInteger.One)
                .Build();

            var certConf = RoundTrip(new ProtectedPkiMessageBuilder(subjectName, ca.Name)
                .SetTransactionId(transactionID)
                .SetBody(PkiBody.TYPE_CERT_CONFIRM, confirmation)
                .Build(new PKMacBuilder().Build(SharedSecret)));

            // 5. CA: check the confirmation is for the certificate it issued, and acknowledge with pkiConf.
            Assert.True(certConf.Verify(new PKMacBuilder(), SharedSecret), subjectAlgorithm + ": certConf protection");

            var statuses = CertificateConfirmationContent.FromPkiBody(certConf.Body).GetStatusMessages();
            Assert.AreEqual(1, statuses.Length);
            Assert.AreEqual(BigInteger.One, statuses[0].CertReqID.Value);
            Assert.True(statuses[0].IsVerified(issued), caAlgorithm + ": certHash of the issued certificate");

            var pkiConf = RoundTrip(ca.Protect(new ProtectedPkiMessageBuilder(ca.Name, subjectName)
                .SetTransactionId(transactionID)
                .SetBody(new PkiBody(PkiBody.TYPE_CONFIRM, DerNull.Instance))));

            ca.CheckProtection(pkiConf);
            Assert.AreEqual(PkiBody.TYPE_CONFIRM, pkiConf.Body.Type);
        }

        /// <summary>
        /// A certification request (cr) from a subject that already holds a composite certificate, protected by
        /// a signature with that certificate's key, for a second composite key.
        /// </summary>
        [Test]
        public void TestSignatureProtectedRequest()
        {
            string caAlgorithm = CompositeMLDsaParameters.MLDSA65_ECDSA_P384_SHA512.Name;
            var ca = new CA(caAlgorithm, m_vectorKeys[caAlgorithm]);

            string currentAlgorithm = CompositeMLDsaParameters.MLDSA44_Ed25519_SHA512.Name;
            var currentKeys = m_vectorKeys[currentAlgorithm];
            var subjectDN = new X509Name("CN=Signature-protected Subject,O=Bouncy Castle");
            var subjectName = new GeneralName(subjectDN);
            var currentCertificate = ca.Issue(new CertTemplateBuilder()
                .SetSubject(subjectDN)
                .SetPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(currentKeys.Public))
                .Build());

            string newAlgorithm = CompositeMLDsaParameters.MLDSA87_ECDSA_P521_SHA512.Name;
            var newKeys = m_vectorKeys[newAlgorithm];
            byte[] transactionID = SecureRandom.GetNextBytes(Random, 16);

            var requestBuilder = new CertificateReqMessagesBuilder();
            requestBuilder.AddRequest(new CertificateRequestMessageBuilder(BigInteger.One)
                .SetSubject(subjectDN)
                .SetPublicKey(newKeys.Public)
                .SetProofOfPossessionSignKeySigner(new Asn1SignatureFactory(newAlgorithm, newKeys.Private, Random))
                .Build());

            var cr = RoundTrip(new ProtectedPkiMessageBuilder(subjectName, ca.Name)
                .SetTransactionId(transactionID)
                .SetBody(PkiBody.TYPE_CERT_REQ, requestBuilder.Build())
                .AddCmpCertificate(currentCertificate)
                .Build(new Asn1SignatureFactory(currentAlgorithm, currentKeys.Private, Random)));

            // CA: the protecting certificate comes with the message; it must chain to the CA and verify the message.
            CheckAlgorithm(currentAlgorithm, cr.ProtectionAlgorithm, "cr protection");
            Assert.False(cr.HasPasswordBasedMacProtected);

            var senderCertificate = cr.GetCertificates()[0];
            senderCertificate.Verify(ca.Certificate.GetPublicKey());
            Assert.True(cr.Verify(senderCertificate.GetPublicKey()), "cr protection");

            var request = CertificateReqMessages.FromPkiBody(cr.Body).GetRequests()[0];
            var issued = ca.Issue(CheckSigningKeyPop(newAlgorithm, request));

            var cp = RoundTrip(ca.Protect(new ProtectedPkiMessageBuilder(ca.Name, subjectName)
                .SetTransactionId(transactionID)
                .SetBody(PkiBody.TYPE_CERT_REP, new CertificateRepMessageBuilder(ca.Certificate)
                    .AddCertificateResponse(new CertificateResponseBuilder(request.GetCertReqID(),
                        new PkiStatusInfo(PkiStatusEncodable.granted)).WithCertificate(issued).Build())
                    .Build())));

            CheckCertificateResponse(ca, cp, PkiBody.TYPE_CERT_REP, newKeys.Public);
        }

        private static CertTemplate CheckSigningKeyPop(string algorithm, CertificateRequestMessage request)
        {
            Assert.True(request.HasProofOfPossession, algorithm + ": POP present");
            Assert.AreEqual(CertificateRequestMessage.popSigningKey, request.ProofOfPossession,
                algorithm + ": POP type");

            var pop = PopoSigningKey.GetInstance(request.ToAsn1Structure().Pop.Object);
            CheckAlgorithm(algorithm, pop.AlgorithmIdentifier, "POP");

            var template = request.GetCertTemplate();
            var requestedKey = PublicKeyFactory.CreateKey(template.PublicKey);
            Assert.True(request.IsValidSigningKeyPop(new Asn1VerifierFactoryProvider(requestedKey)),
                algorithm + ": POP signature");

            return template;
        }

        private static X509Certificate CheckCertificateResponse(CA ca, ProtectedPkiMessage message, int bodyType,
            AsymmetricKeyParameter expectedPublicKey)
        {
            ca.CheckProtection(message);
            Assert.AreEqual(bodyType, message.Body.Type);

            var repMessage = CertificateRepMessage.FromPkiBody(message.Body);
            var caPubs = repMessage.GetX509Certificates();
            Assert.AreEqual(1, caPubs.Length, "caPubs");
            Assert.AreEqual(ca.Certificate, caPubs[0], "caPubs");

            var responses = repMessage.GetResponses();
            Assert.AreEqual(1, responses.Length);
            Assert.AreEqual(BigInteger.One, responses[0].ToAsn1Structure().CertReqID.Value);
            Assert.AreEqual((int)PkiStatus.Granted, responses[0].ToAsn1Structure().Status.Status.IntValueExact);
            Assert.False(responses[0].HasEncryptedCertificate);

            var certificate = new X509Certificate(responses[0].GetCertificate().X509v3PKCert);
            certificate.Verify(ca.Certificate.GetPublicKey());
            CheckAlgorithm(ca.Algorithm, certificate.SignatureAlgorithm, "issued certificate");
            Assert.AreEqual(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(expectedPublicKey),
                certificate.SubjectPublicKeyInfo, "issued certificate key");

            return certificate;
        }

        private static void CheckAlgorithm(string algorithm, AlgorithmIdentifier algID, string what)
        {
            Assert.AreEqual(SignerUtilities.GetObjectIdentifier(algorithm), algID.Algorithm,
                algorithm + ": " + what + " signature algorithm");
            Assert.IsNull(algID.Parameters, algorithm + ": " + what + " AlgorithmIdentifier must omit parameters");
        }

        /// <summary>Encode and re-parse, as the message would travel.</summary>
        private static ProtectedPkiMessage RoundTrip(ProtectedPkiMessage message) =>
            new ProtectedPkiMessage(new GeneralPkiMessage(message.ToAsn1Message().GetEncoded()));

        private sealed class CA
        {
            private readonly AsymmetricKeyParameter m_privateKey;
            private int m_lastSerialNumber = 1;

            internal CA(string algorithm, AsymmetricCipherKeyPair keyPair)
            {
                var caDN = new X509Name("CN=" + algorithm + " CA,O=Bouncy Castle");

                Algorithm = algorithm;
                Name = new GeneralName(caDN);
                m_privateKey = keyPair.Private;

                DateTime now = DateTime.UtcNow;

                var certGen = new X509V3CertificateGenerator();
                certGen.SetSerialNumber(BigInteger.One);
                certGen.SetIssuerDN(caDN);
                certGen.SetSubjectDN(caDN);
                certGen.SetNotBefore(now.AddMinutes(-5));
                certGen.SetNotAfter(now.AddDays(1));
                certGen.SetPublicKey(keyPair.Public);
                certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(true));
                certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                    new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));

                Certificate = certGen.Generate(SignatureFactory);
            }

            internal string Algorithm { get; }

            internal X509Certificate Certificate { get; }

            internal GeneralName Name { get; }

            private ISignatureFactory SignatureFactory => new Asn1SignatureFactory(Algorithm, m_privateKey, Random);

            internal X509Certificate Issue(CertTemplate template)
            {
                DateTime now = DateTime.UtcNow;

                var certGen = new X509V3CertificateGenerator();
                certGen.SetSerialNumber(BigInteger.ValueOf(++m_lastSerialNumber));
                certGen.SetIssuerDN(Certificate.SubjectDN);
                certGen.SetSubjectDN(template.Subject);
                certGen.SetNotBefore(now.AddMinutes(-5));
                certGen.SetNotAfter(now.AddHours(1));
                certGen.SetSubjectPublicKeyInfo(template.PublicKey);
                certGen.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(false));
                certGen.AddExtension(X509Extensions.KeyUsage, critical: true,
                    new KeyUsage(KeyUsage.DigitalSignature));

                return certGen.Generate(SignatureFactory);
            }

            internal ProtectedPkiMessage Protect(ProtectedPkiMessageBuilder builder) =>
                builder.AddCmpCertificate(Certificate).Build(SignatureFactory);

            /// <summary>The subject's side: the CA's message, checked against the CA certificate it trusts.</summary>
            internal void CheckProtection(ProtectedPkiMessage message)
            {
                CheckAlgorithm(Algorithm, message.ProtectionAlgorithm, "message protection");
                Assert.False(message.HasPasswordBasedMacProtected);

                var extraCerts = message.GetCertificates();
                Assert.AreEqual(1, extraCerts.Length, "extraCerts");
                Assert.AreEqual(Certificate, extraCerts[0], "extraCerts");

                Assert.True(message.Verify(Certificate.GetPublicKey()), Algorithm + ": message protection");
            }
        }
    }
}
