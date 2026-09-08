using System.Collections.Generic;

using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// Generates the configurations that <see cref="TlsTestCase"/> and <see cref="DtlsTestCase"/> run, one NUnit test
    /// case each. The same generator serves both: cases that only apply to some versions are guarded by version, so
    /// the TLS 1.3 cases simply do not arise for DTLS.
    /// </summary>
    public class TlsTestSuite
    {
        // Make the access to constants less verbose
        internal abstract class C : TlsTestConfig {}

        public static IEnumerable<TestCaseData> Suite() =>
            Generate(ProtocolVersion.TLSv13.DownTo(ProtocolVersion.SSLv3));

        /// <param name="versions">The protocol versions to generate cases for, highest first; all TLS or all DTLS.
        /// </param>
        internal static IEnumerable<TestCaseData> Generate(ProtocolVersion[] versions)
        {
            var testSuite = new List<TestCaseData>();

            AddFallbackTests(testSuite, versions);

            for (int i = versions.Length - 1; i >= 0; --i)
            {
                AddVersionTests(testSuite, versions, versions[i]);
            }

            return testSuite;
        }

        /// <summary>Check that a case ended the way its configuration says it should.</summary>
        internal static void AssertExpectedOutcome(TlsTestConfig config, TlsTestClientImpl clientImpl,
            TlsTestServerImpl serverImpl, LoopbackResult result)
        {
            if (config.expectFatalAlertConnectionEnd == -1)
            {
                result.ThrowIfFailed();
            }

            Assert.AreEqual(config.expectFatalAlertConnectionEnd, clientImpl.FirstFatalAlertConnectionEnd,
                "Client fatal alert connection end");
            Assert.AreEqual(config.expectFatalAlertConnectionEnd, serverImpl.FirstFatalAlertConnectionEnd,
                "Server fatal alert connection end");

            Assert.AreEqual(config.expectFatalAlertDescription, clientImpl.FirstFatalAlertDescription,
                "Client fatal alert description");
            Assert.AreEqual(config.expectFatalAlertDescription, serverImpl.FirstFatalAlertDescription,
                "Server fatal alert description");
        }

        private static void AddFallbackTests(IList<TestCaseData> testSuite, ProtocolVersion[] versions)
        {
            // TLS_FALLBACK_SCSV (RFC 7507) is tested against a server whose maximum version is (D)TLS 1.2
            ProtocolVersion serverMaxVersion = FindVersion12(versions);

            // A client that has fallen back offers the two versions below that (or the one, for DTLS)
            ProtocolVersion fallbackMax = serverMaxVersion.GetPreviousVersion();
            ProtocolVersion[] fallbackVersions = fallbackMax.DownTo(fallbackMax.GetPreviousVersion() ?? fallbackMax);

            {
                TlsTestConfig c = CreateTestConfig(versions, serverMaxVersion);
                c.clientFallback = true;

                AddTestCase(testSuite, c, "FallbackGood");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, serverMaxVersion);
                c.clientFallback = true;
                c.clientSupportedVersions = fallbackVersions;
                c.ExpectServerFatalAlert(AlertDescription.inappropriate_fallback);

                AddTestCase(testSuite, c, "FallbackBad");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, serverMaxVersion);
                c.clientSupportedVersions = fallbackVersions;

                AddTestCase(testSuite, c, "FallbackNone");
            }
        }

        private static void AddVersionTests(IList<TestCaseData> testSuite, ProtocolVersion[] versions,
            ProtocolVersion version)
        {
            string prefix = version.ToString().Replace(" ", "").Replace(".", "") + "_";

            bool isTlsV12 = TlsUtilities.IsTlsV12(version);
            bool isTlsV13 = TlsUtilities.IsTlsV13(version);
            bool isTlsV12Exactly = isTlsV12 && !isTlsV13;

            short certReqDeclinedAlert = isTlsV13
                ?   AlertDescription.certificate_required
                :   AlertDescription.handshake_failure;

            {
                TlsTestConfig c = CreateTestConfig(versions, version);

                AddTestCase(testSuite, c, prefix + "GoodDefault");
            }

            if (isTlsV13)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientEmptyKeyShare = true;

                AddTestCase(testSuite, c, prefix + "GoodEmptyKeyShare");
            }

            /*
             * Server only declares support for SHA256/ECDSA, client selects SHA256/RSA, so we expect fatal alert
             * from the client validation of the CertificateVerify algorithm.
             */
            if (isTlsV12Exactly)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                c.serverCertReqSigAlgs = TlsUtilities.VectorOfOne(
                    new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
                c.ExpectClientFatalAlert(AlertDescription.internal_error);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySigAlgClient");
            }

            /*
             * Server only declares support for rsa_pss_rsae_sha256, client selects rsa_pss_rsae_sha256 but claims
             * ecdsa_secp256r1_sha256, so we expect fatal alert from the server validation of the
             * CertificateVerify algorithm.
             */
            if (isTlsV12)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                c.clientAuthSigAlgClaimed = SignatureScheme.GetSignatureAndHashAlgorithm(
                    SignatureScheme.ecdsa_secp256r1_sha256);
                c.serverCertReqSigAlgs = TlsUtilities.VectorOfOne(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                c.serverCheckSigAlgOfClientCerts = false;
                c.ExpectServerFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer1");
            }

            /*
             * Server declares support for rsa_pss_rsae_sha256 and ecdsa_secp256r1_sha256, client selects
             * rsa_pss_rsae_sha256 but claims ecdsa_secp256r1_sha256, so we expect fatal alert from the server
             * validation of the client certificate.
             */
            if (isTlsV12)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                c.clientAuthSigAlgClaimed = SignatureScheme.GetSignatureAndHashAlgorithm(
                    SignatureScheme.ecdsa_secp256r1_sha256);
                c.serverCertReqSigAlgs = new List<SignatureAndHashAlgorithm>(2);
                c.serverCertReqSigAlgs.Add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                c.serverCertReqSigAlgs.Add(
                    SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256));
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer2");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
                c.ExpectServerFatalAlert(AlertDescription.decrypt_error);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySignature");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadClientCertificate");
            }

            if (isTlsV13)
            {
                /*
                 * For TLS 1.3 the supported_algorithms extension is required in ClientHello when the
                 * server authenticates via a certificate.
                 */
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.ExpectServerFatalAlert(AlertDescription.missing_extension);

                AddTestCase(testSuite, c, prefix + "BadClientSigAlgs");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_NONE;
                c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
                c.ExpectServerFatalAlert(certReqDeclinedAlert);

                AddTestCase(testSuite, c, prefix + "BadMandatoryCertReqDeclined");
            }

            /*
             * Server sends SHA-256/RSA certificate, which is not the default {sha1,rsa} implied by the
             * absent signature_algorithms extension. We expect fatal alert from the client when it
             * verifies the certificate's 'signatureAlgorithm' against the implicit default signature_algorithms.
             */
            if (isTlsV12Exactly)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                c.ExpectClientFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadServerCertSigAlg");
            }

            /*
             * Client declares support for SHA256/RSA, server selects SHA384/RSA, so we expect fatal alert from the
             * client validation of the ServerKeyExchange algorithm.
             */
            if (isTlsV12)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientCHSigAlgs = TlsUtilities.VectorOfOne(
                    new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
                c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha384, SignatureAlgorithm.rsa);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg");
            }

            /*
             * Server selects SHA256/RSA for ServerKeyExchange signature, which is not the default {sha1,rsa} implied by
             * the absent signature_algorithms extension. We expect fatal alert from the client when it verifies the
             * selected algorithm against the implicit default.
             */
            if (isTlsV12Exactly)
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientCheckSigAlgOfServerCerts = false;
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.serverCertReq = C.SERVER_CERT_REQ_NONE;

                AddTestCase(testSuite, c, prefix + "GoodNoCertReq");
            }

            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.clientAuth = C.CLIENT_AUTH_NONE;

                AddTestCase(testSuite, c, prefix + "GoodOptionalCertReqDeclined");
            }

            /*
             * Server generates downgraded (RFC 8446) ServerHello. We expect fatal alert (illegal_parameter) from the
             * client. Only where there is a higher version for the server to be downgrading from.
             */
            if (version != versions[0])
            {
                TlsTestConfig c = CreateTestConfig(versions, version);
                c.serverNegotiateVersion = version;
                c.serverSupportedVersions = versions[0].DownTo(version);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadDowngrade");
            }
        }

        private static void AddTestCase(IList<TestCaseData> testSuite, TlsTestConfig config, string name)
        {
            testSuite.Add(new TestCaseData(config).SetName(name));
        }

        /// <summary>A configuration with the client supporting every version and the server supporting every version
        /// up to the given one.</summary>
        private static TlsTestConfig CreateTestConfig(ProtocolVersion[] versions, ProtocolVersion serverMaxVersion)
        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientSupportedVersions = versions;
            c.serverSupportedVersions = serverMaxVersion.DownTo(versions[versions.Length - 1]);
            return c;
        }

        private static ProtocolVersion FindVersion12(ProtocolVersion[] versions)
        {
            foreach (ProtocolVersion version in versions)
            {
                if (TlsUtilities.IsTlsV12(version) && !TlsUtilities.IsTlsV13(version))
                    return version;
            }

            throw new System.ArgumentException("no (D)TLS 1.2 version", nameof(versions));
        }
    }
}
