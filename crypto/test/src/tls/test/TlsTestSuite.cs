﻿using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    public class TlsTestSuite
    {
        internal static TlsCrypto BC_CRYPTO = new BcTlsCrypto();

        internal static TlsCrypto GetCrypto(TlsTestConfig config)
        {
            switch (config.clientCrypto)
            {
                case TlsTestConfig.CRYPTO_BC:
                default:
                    return BC_CRYPTO;
            }
        }

        // Make the access to constants less verbose 
        internal abstract class C : TlsTestConfig {}

        public TlsTestSuite()
        {
        }

        public static IEnumerable<TestCaseData> Suite()
        {
            var testSuite = new List<TestCaseData>();
            AddAllTests(testSuite, TlsTestConfig.CRYPTO_BC, TlsTestConfig.CRYPTO_BC);
            return testSuite;
        }

        private static void AddAllTests(IList<TestCaseData> testSuite, int clientCrypto, int serverCrypto)
        {
            AddFallbackTests(testSuite, clientCrypto, serverCrypto);
            AddVersionTests(testSuite, ProtocolVersion.SSLv3, clientCrypto, serverCrypto);
            AddVersionTests(testSuite, ProtocolVersion.TLSv10, clientCrypto, serverCrypto);
            AddVersionTests(testSuite, ProtocolVersion.TLSv11, clientCrypto, serverCrypto);
            AddVersionTests(testSuite, ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
            AddVersionTests(testSuite, ProtocolVersion.TLSv13, clientCrypto, serverCrypto);
        }

        private static void AddFallbackTests(IList<TestCaseData> testSuite, int clientCrypto, int serverCrypto)
        {
            string prefix = GetCryptoName(clientCrypto) + "_" + GetCryptoName(serverCrypto) + "_";

            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
                c.clientFallback = true;

                AddTestCase(testSuite, c, prefix + "FallbackGood");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
                c.clientFallback = true;
                c.clientSupportedVersions = ProtocolVersion.TLSv11.DownTo(ProtocolVersion.TLSv10);
                c.ExpectServerFatalAlert(AlertDescription.inappropriate_fallback);

                AddTestCase(testSuite, c, prefix + "FallbackBad");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
                c.clientSupportedVersions = ProtocolVersion.TLSv11.DownTo(ProtocolVersion.TLSv10);

                AddTestCase(testSuite, c, prefix + "FallbackNone");
            }
        }

        private static void AddVersionTests(IList<TestCaseData> testSuite, ProtocolVersion version, int clientCrypto,
            int serverCrypto)
        {
            string prefix = GetCryptoName(clientCrypto) + "_" + GetCryptoName(serverCrypto) + "_"
                + version.ToString().Replace(" ", "").Replace(".", "") + "_";

            bool isTlsV12 = TlsUtilities.IsTlsV12(version);
            bool isTlsV13 = TlsUtilities.IsTlsV13(version);
            bool isTlsV12Exactly = isTlsV12 && !isTlsV13;

            short certReqDeclinedAlert = TlsUtilities.IsTlsV13(version)
                ?   AlertDescription.certificate_required
                :   AlertDescription.handshake_failure;

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);

                AddTestCase(testSuite, c, prefix + "GoodDefault");
            }

            if (isTlsV13)
            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientEmptyKeyShare = true;

                AddTestCase(testSuite, c, prefix + "GoodEmptyKeyShare");
            }

            /*
             * Server only declares support for SHA256/ECDSA, client selects SHA256/RSA, so we expect fatal alert
             * from the client validation of the CertificateVerify algorithm.
             */
            if (isTlsV12Exactly)
            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
            if (isTlsV12)
            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientAuth = C.CLIENT_AUTH_VALID;
                c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                c.clientAuthSigAlgClaimed = SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
                c.serverCertReqSigAlgs = new List<SignatureAndHashAlgorithm>(2);
                c.serverCertReqSigAlgs.Add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                c.serverCertReqSigAlgs.Add(
                    SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256));
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer2");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
                c.ExpectServerFatalAlert(AlertDescription.decrypt_error);

                AddTestCase(testSuite, c, prefix + "BadCertVerifySignature");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.ExpectServerFatalAlert(AlertDescription.missing_extension);

                AddTestCase(testSuite, c, prefix + "BadClientSigAlgs");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
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
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientCheckSigAlgOfServerCerts = false;
                c.clientSendSignatureAlgorithms = false;
                c.clientSendSignatureAlgorithmsCert = false;
                c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.serverCertReq = C.SERVER_CERT_REQ_NONE;

                AddTestCase(testSuite, c, prefix + "GoodNoCertReq");
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.clientAuth = C.CLIENT_AUTH_NONE;

                AddTestCase(testSuite, c, prefix + "GoodOptionalCertReqDeclined");
            }

            /*
             * Server generates downgraded (RFC 8446) 1.1 ServerHello. We expect fatal alert
             * (illegal_parameter) from the client.
             */
            if (!isTlsV13)
            {
                TlsTestConfig c = CreateTlsTestConfig(version, clientCrypto, serverCrypto);
                c.serverNegotiateVersion = version;
                c.serverSupportedVersions = ProtocolVersion.TLSv13.DownTo(version);
                c.ExpectClientFatalAlert(AlertDescription.illegal_parameter);

                AddTestCase(testSuite, c, prefix + "BadDowngrade");
            }
        }

        private static void AddTestCase(IList<TestCaseData> testSuite, TlsTestConfig config, string name)
        {
            testSuite.Add(new TestCaseData(config).SetName(name));
        }

        private static TlsTestConfig CreateTlsTestConfig(ProtocolVersion serverMaxVersion, int clientCrypto,
            int serverCrypto)
        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientCrypto = clientCrypto;
            c.clientSupportedVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.SSLv3);
            c.serverCrypto = serverCrypto;
            c.serverSupportedVersions = serverMaxVersion.DownTo(ProtocolVersion.SSLv3);
            return c;
        }

        private static string GetCryptoName(int crypto)
        {
            switch (crypto)
            {
            case TlsTestConfig.CRYPTO_BC:
            default:
                return "BC";
            }
        }
    }
}
