using System;
using System.Collections;

using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    public class DtlsTestSuite
    {
        // Make the access to constants less verbose 
        internal class C : TlsTestConfig {}

        public DtlsTestSuite()
        {
        }

        public static IEnumerable Suite()
        {
            IList testSuite = new ArrayList();

            AddFallbackTests(testSuite);
            AddVersionTests(testSuite, ProtocolVersion.DTLSv10);
            AddVersionTests(testSuite, ProtocolVersion.DTLSv12);

            return testSuite;
        }

        private static void AddFallbackTests(IList testSuite)
        {
            {
                TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
                c.clientFallback = true;

                AddTestCase(testSuite, c, "FallbackGood");
            }

            /*
             * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
             * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
             * alerts being raised
             */

#if false
            {
                TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
                c.clientFallback = true;
                c.clientSupportedVersions = ProtocolVersion.DTLSv10.Only();
                c.ExpectServerFatalAlert(AlertDescription.inappropriate_fallback);

                AddTestCase(testSuite, c, "FallbackBad");
            }
#endif

            {
                TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
                c.clientSupportedVersions = ProtocolVersion.DTLSv10.Only();

                AddTestCase(testSuite, c, "FallbackNone");
            }
        }

        private static void AddVersionTests(IList testSuite, ProtocolVersion version)
        {
            string prefix = version.ToString()
                .Replace(" ", "")
                .Replace("\\", "")
                .Replace(".", "")
                + "_";

            /*
             * Server only declares support for SHA256/ECDSA, client selects SHA256/RSA, so we expect fatal alert
             * from the client validation of the CertificateVerify algorithm.
             */
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
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
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                c.clientAuthSigAlgClaimed = SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
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
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                c.clientAuthSigAlgClaimed = SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
                c.serverCertReqSigAlgs = new ArrayList(2);
                c.serverCertReqSigAlgs.Add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                c.serverCertReqSigAlgs.Add(
                    SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256));
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer2");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
                c.ExpectServerFatalAlert(AlertDescription.decrypt_error);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySignature");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadClientCertificate");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_NONE;
                c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
                c.ExpectServerFatalAlert(AlertDescription.handshake_failure);

                AddTestCase(testSuite, c, prefix + "BadMandatoryCertReqDeclined");
            }

            /*
             * Server sends SHA-256/RSA certificate, which is not the default {sha1,rsa} implied by the
             * absent signature_algorithms extension. We expect fatal alert from the client when it
             * verifies the certificate's 'signatureAlgorithm' against the implicit default signature_algorithms.
             */
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
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
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
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
            if (TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientCheckSigAlgOfServerCerts = false;
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);

                AddTestCase(testSuite, c, prefix + "GoodDefault");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.serverCertReq = C.SERVER_CERT_REQ_NONE;

                AddTestCase(testSuite, c, prefix + "GoodNoCertReq");
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_NONE;

                AddTestCase(testSuite, c, prefix + "GoodOptionalCertReqDeclined");
            }

            /*
             * Server generates downgraded (RFC 8446) ServerHello. We expect fatal alert
             * (illegal_parameter) from the client.
             */
            if (!TlsUtilities.IsTlsV12(version))
            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.serverNegotiateVersion = version;
                c.serverSupportedVersions = ProtocolVersion.DTLSv12.DownTo(version);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadDowngrade");
            }
        }

        private static void AddTestCase(IList testSuite, TlsTestConfig config, string name)
        {
            testSuite.Add(new TestCaseData(config).SetName(name));
        }

        private static TlsTestConfig CreateDtlsTestConfig(ProtocolVersion serverMaxVersion)
        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientSupportedVersions = ProtocolVersion.DTLSv12.DownTo(ProtocolVersion.DTLSv10);
            c.serverSupportedVersions = serverMaxVersion.DownTo(ProtocolVersion.DTLSv10);
            return c;
        }

        public static void RunTests()
        {
            foreach (TestCaseData data in Suite())
            {
                Console.WriteLine(data.TestName);
                new DtlsTestCase().RunTest((TlsTestConfig)data.Arguments[0]);
            }
        }
    }
}
