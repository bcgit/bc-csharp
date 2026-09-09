using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tls.Tests
{
    public class TlsTestUtilities
    {
        private static readonly ConcurrentDictionary<string, PemObject> PemObjectCache =
            new ConcurrentDictionary<string, PemObject>();

        internal static readonly byte[] RsaCertData = Base64.Decode(
            "MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" +
            "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" +
            "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA2MDIwNVoXDTEzMDIyNT" +
            "A2MDM0NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" +
            "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" +
            "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" +
            "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCBSAwEgYDVR" +
            "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAHU55Ncz" +
            "eglREcTg54YLUlGWu2WOYWhit/iM1eeq8Kivro7q98eW52jTuMI3CI5ulqd0hYzshQKQaZ5GDzErMyM=");

        internal static readonly byte[] DudRsaCertData = Base64.Decode(
            "MIICUzCCAf2gAwIBAgIBATANBgkqhkiG9w0BAQQFADCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb2" +
            "4gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkq" +
            "hkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTEzMDIyNTA1NDcyOFoXDTEzMDIyNT" +
            "A1NDkwOFowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIw" +
            "EAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG" +
            "9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4Shy" +
            "pL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR" +
            "0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAJg55PBS" +
            "weg6obRUKF4FF6fCrWFi6oCYSQ99LWcAeupc5BofW5MstFMhCOaEucuGVqunwT5G7/DweazzCIrSzB0=");

        internal static TlsPskIdentity CreateDefaultPskIdentity(bool badKey) =>
            new BasicTlsPskIdentity("client", GetPskPasswordUtf8(badKey));

        internal static bool EqualsIgnoreCase(string a, string b) =>
            string.Equals(a, b, StringComparison.InvariantCultureIgnoreCase);

        internal static string Fingerprint(X509CertificateStructure c)
        {
            byte[] der = c.GetEncoded();
            byte[] hash = Sha256DigestOf(der);
            byte[] hexBytes = Hex.Encode(hash);
            string hex = Encoding.ASCII.GetString(hexBytes).ToUpperInvariant();

            StringBuilder fp = new StringBuilder();
            int i = 0;
            fp.Append(hex.Substring(i, 2));
            while ((i += 2) < hex.Length)
            {
                fp.Append(':');
                fp.Append(hex.Substring(i, 2));
            }
            return fp.ToString();
        }

        internal static byte[] Sha256DigestOf(byte[] input)
        {
            return DigestUtilities.CalculateDigest("SHA256", input);
        }

        /*
         * Shared peer behaviour: what every test client/server does the same way, so that a mock peer holds only
         * what is particular to it. All logging is gated on TlsTestConfig.Debug.
         */

        /// <summary>The end-entity certificates a test client trusts a server to present.</summary>
        internal static readonly string[] TrustedServerCertResources = new string[]{ "x509-server-dsa.pem",
            "x509-server-ecdh.pem", "x509-server-ecdsa.pem", "x509-server-ed25519.pem", "x509-server-ed448.pem",
            "x509-server-ml_dsa_44.pem", "x509-server-ml_dsa_65.pem", "x509-server-ml_dsa_87.pem",
            "x509-server-rsa_pss_256.pem", "x509-server-rsa_pss_384.pem", "x509-server-rsa_pss_512.pem",
            "x509-server-rsa-enc.pem", "x509-server-rsa-sign.pem" };

        /// <summary>The end-entity certificates a test server trusts a client to present.</summary>
        internal static readonly string[] TrustedClientCertResources = new string[]{ "x509-client-dsa.pem",
            "x509-client-ecdh.pem", "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem",
            "x509-client-ml_dsa_44.pem", "x509-client-ml_dsa_65.pem", "x509-client-ml_dsa_87.pem",
            "x509-client-rsa_pss_256.pem", "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",
            "x509-client-rsa.pem" };

        /// <summary>Extensions the test clients add to their ClientHello to exercise the code paths.</summary>
        /// <remarks>NOTE: If you are copying test code, do not blindly set these extensions in your own client.
        /// </remarks>
        internal static void AddTestClientExtensions(IDictionary<int, byte[]> clientExtensions, TlsContext context)
        {
            TlsExtensionsUtilities.AddMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
            TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, context.Crypto.SecureRandom.Next(16));
            TlsExtensionsUtilities.AddTruncatedHmacExtension(clientExtensions);
        }

        internal static void CheckClientRandom(TlsContext context)
        {
            if (context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        internal static void CheckServerRandom(TlsContext context)
        {
            if (context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <param name="sigAlgs">The signature algorithms to request, or null for the defaults; ignored where the
        /// negotiated version has no signature_algorithms extension.</param>
        internal static CertificateRequest CreateCertificateRequest(TlsContext context,
            IList<SignatureAndHashAlgorithm> sigAlgs)
        {
            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(context.ServerVersion))
            {
                serverSigAlgs = sigAlgs ?? TlsUtilities.GetDefaultSupportedSignatureAlgorithms(context);
            }

            // All the CA certificates are currently configured with this subject
            var certificateAuthorities = new List<X509Name>{ new X509Name("CN=BouncyCastle TLS Test CA") };

            if (TlsUtilities.IsTlsV13(context))
            {
                // TODO[tls13] Support for non-empty request context
                byte[] certificateRequestContext = TlsUtilities.EmptyBytes;

                // TODO[tls13] Add support for signature_algorithms_cert
                IList<SignatureAndHashAlgorithm> serverSigAlgsCert = null;

                return new CertificateRequest(certificateRequestContext, serverSigAlgs, serverSigAlgsCert,
                    certificateAuthorities);
            }

            short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
                ClientCertificateType.ecdsa_sign };

            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
        }

        internal static TlsCredentialedDecryptor LoadServerEncryptionCredentials(TlsContext context)
        {
            return LoadEncryptionCredentials(context, new string[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
                "x509-server-key-rsa-enc.pem");
        }

        internal static void Log(string message)
        {
            if (TlsTestConfig.Debug)
            {
                Console.WriteLine(message);
            }
        }

        internal static void Log(string format, params object[] args)
        {
            if (TlsTestConfig.Debug)
            {
                Console.WriteLine(format, args);
            }
        }

        internal static void LogAlert(string peerName, bool raised, short alertLevel, short alertDescription,
            string message, Exception cause)
        {
            if (!TlsTestConfig.Debug)
                return;

            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine(peerName + (raised ? " raised alert: " : " received alert: ")
                + AlertLevel.GetText(alertLevel) + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        internal static void LogException(string context, Exception e)
        {
            if (TlsTestConfig.Debug)
            {
                Console.Error.WriteLine(context + ": " + e);
                Console.Error.Flush();
            }
        }

        /// <summary>Log the negotiated ALPN protocol and group, and the channel bindings, of a completed handshake.
        /// </summary>
        internal static void LogHandshakeComplete(string peerName, TlsContext context)
        {
            if (!TlsTestConfig.Debug)
                return;

            SecurityParameters securityParameters = context.SecurityParameters;

            ProtocolName protocolName = securityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine(peerName + " ALPN: " + protocolName.GetUtf8Decoding());
            }

            int negotiatedGroup = securityParameters.NegotiatedGroup;
            if (negotiatedGroup >= 0)
            {
                Console.WriteLine(peerName + " negotiated group: " + NamedGroup.GetText(negotiatedGroup));
            }

            Console.WriteLine(peerName + " 'tls-server-end-point': "
                + ToHexString(context.ExportChannelBinding(ChannelBinding.tls_server_end_point)));
            Console.WriteLine(peerName + " 'tls-unique': "
                + ToHexString(context.ExportChannelBinding(ChannelBinding.tls_unique)));

            if (securityParameters.IsExtendedMasterSecret)
            {
                Console.WriteLine(peerName + " 'tls-exporter': "
                    + ToHexString(context.ExportChannelBinding(ChannelBinding.tls_exporter)));
            }
        }

        /// <summary>The session a client should keep for resumption after a completed handshake: the new session if
        /// it is resumable, otherwise whatever it held before.</summary>
        internal static TlsSession NoteSession(string peerName, TlsSession previousSession, TlsContext context)
        {
            TlsSession newSession = context.Session;
            if (newSession == null || !newSession.IsResumable)
                return previousSession;

            if (TlsTestConfig.Debug)
            {
                byte[] newSessionID = newSession.SessionID;
                bool resumed = previousSession != null && Arrays.AreEqual(previousSession.SessionID, newSessionID);

                Console.WriteLine(peerName + (resumed ? " resumed session: " : " established session: ")
                    + ToHexString(newSessionID));
            }

            return newSession;
        }

        /// <summary>The default client credentials: the RSA test client certificate, if the request admits it.
        /// </summary>
        internal static TlsCredentials SelectRsaClientCredentials(TlsContext context,
            CertificateRequest certificateRequest)
        {
            short[] certificateTypes = certificateRequest.CertificateTypes;
            if (certificateTypes == null || !Arrays.Contains(certificateTypes, ClientCertificateType.rsa_sign))
                return null;

            return LoadSignerCredentials(context, certificateRequest.SupportedSignatureAlgorithms,
                SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
        }

        internal static string ToHexString(byte[] data) => data == null ? "(null)" : Hex.ToHexString(data);

        /// <summary>Check a client certificate against a list of trusted end-entity certificates. An empty
        /// certificate, the client declining to authenticate, passes.</summary>
        /// <exception cref="TlsFatalAlert">bad_certificate if the certificate is not trusted.</exception>
        internal static void VerifyClientCertificate(TlsContext context, Certificate clientCertificate,
            string[] trustedCertResources, bool checkSigAlgs)
        {
            if (clientCertificate == null || clientCertificate.IsEmpty)
                return;

            VerifyPeerCertificate("client", context, clientCertificate.GetCertificateList(), trustedCertResources,
                checkSigAlgs);
        }

        /// <summary>Check a server certificate against a list of trusted end-entity certificates.</summary>
        /// <exception cref="TlsFatalAlert">bad_certificate if the certificate is empty or not trusted.</exception>
        internal static void VerifyServerCertificate(TlsContext context, TlsServerCertificate serverCertificate,
            string[] trustedCertResources, bool checkSigAlgs)
        {
            Certificate certificate = serverCertificate?.Certificate;
            if (certificate == null || certificate.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            VerifyPeerCertificate("server", context, certificate.GetCertificateList(), trustedCertResources,
                checkSigAlgs);
        }

        private static void VerifyPeerCertificate(string peerRole, TlsContext context, TlsCertificate[] chain,
            string[] trustedCertResources, bool checkSigAlgs)
        {
            if (TlsTestConfig.Debug)
            {
                Console.WriteLine("Received " + peerRole + " certificate chain of length " + chain.Length);
                for (int i = 0; i < chain.Length; ++i)
                {
                    X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    Console.WriteLine("    fingerprint:SHA-256 " + Fingerprint(entry) + " (" + entry.Subject + ")");
                }
            }

            TlsCertificate[] certPath = GetTrustedCertPath(context.Crypto, chain[0], trustedCertResources);
            if (certPath == null)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            if (checkSigAlgs)
            {
                TlsUtilities.CheckPeerSigAlgs(context, certPath);
            }
        }

        internal static string GetCACertResource(short signatureAlgorithm)
        {
            return "x509-ca-" + GetResourceName12(signatureAlgorithm, forServer: false) + ".pem";
        }

        internal static string GetCACertResource(string eeCertResource)
        {
            if (eeCertResource.StartsWith("x509-client-"))
            {
                eeCertResource = eeCertResource.Substring("x509-client-".Length);
            }
            if (eeCertResource.StartsWith("x509-server-"))
            {
                eeCertResource = eeCertResource.Substring("x509-server-".Length);
            }
            if (eeCertResource.EndsWith(".pem"))
            {
                eeCertResource = eeCertResource.Substring(0, eeCertResource.Length - ".pem".Length);
            }

            if (EqualsIgnoreCase("dsa", eeCertResource))
                return GetCACertResource(SignatureAlgorithm.dsa);

            if (EqualsIgnoreCase("ecdh", eeCertResource) ||
                EqualsIgnoreCase("ecdsa", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.ecdsa);
            }

            if (EqualsIgnoreCase("ed25519", eeCertResource))
                return GetCACertResource13(SignatureScheme.ed25519);
            if (EqualsIgnoreCase("ed448", eeCertResource))
                return GetCACertResource13(SignatureScheme.ed448);

            if (eeCertResource.StartsWith("ml_dsa_"))
            {
                if (EqualsIgnoreCase("ml_dsa_44", eeCertResource))
                    return GetCACertResource13(SignatureScheme.mldsa44);
                if (EqualsIgnoreCase("ml_dsa_65", eeCertResource))
                    return GetCACertResource13(SignatureScheme.mldsa65);
                if (EqualsIgnoreCase("ml_dsa_87", eeCertResource))
                    return GetCACertResource13(SignatureScheme.mldsa87);
            }

            if (eeCertResource.StartsWith("slh_dsa_sha2_"))
            {
                if (EqualsIgnoreCase("slh_dsa_sha2_128s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_128s);
                if (EqualsIgnoreCase("slh_dsa_sha2_128f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_128f);
                if (EqualsIgnoreCase("slh_dsa_sha2_192s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_192s);
                if (EqualsIgnoreCase("slh_dsa_sha2_192f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_192f);
                if (EqualsIgnoreCase("slh_dsa_sha2_256s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_256s);
                if (EqualsIgnoreCase("slh_dsa_sha2_256f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_sha2_256f);
            }
            if (eeCertResource.StartsWith("slh_dsa_shake_"))
            {
                if (EqualsIgnoreCase("slh_dsa_shake_128s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_128s);
                if (EqualsIgnoreCase("slh_dsa_shake_128f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_128f);
                if (EqualsIgnoreCase("slh_dsa_shake_192s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_192s);
                if (EqualsIgnoreCase("slh_dsa_shake_192f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_192f);
                if (EqualsIgnoreCase("slh_dsa_shake_256s", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_256s);
                if (EqualsIgnoreCase("slh_dsa_shake_256f", eeCertResource))
                    return GetCACertResource13(SignatureScheme.DRAFT_slhdsa_shake_256f);
            }

            if (EqualsIgnoreCase("rsa", eeCertResource) ||
                EqualsIgnoreCase("rsa-enc", eeCertResource) ||
                EqualsIgnoreCase("rsa-sign", eeCertResource))
            {
                return GetCACertResource(SignatureAlgorithm.rsa);
            }

            if (EqualsIgnoreCase("rsa_pss_256", eeCertResource))
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha256);
            if (EqualsIgnoreCase("rsa_pss_384", eeCertResource))
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha384);
            if (EqualsIgnoreCase("rsa_pss_512", eeCertResource))
                return GetCACertResource(SignatureAlgorithm.rsa_pss_pss_sha512);

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        internal static string GetCACertResource13(int signatureScheme)
        {
            return "x509-ca-" + GetResourceName13(signatureScheme, forServer: false) + ".pem";
        }

        internal static string GetPskPassword(bool badKey) => badKey ? "TLS_TEST_PSK_BAD" : "TLS_TEST_PSK";

        internal static byte[] GetPskPasswordUtf8(bool badKey) => Strings.ToUtf8ByteArray(GetPskPassword(badKey));

        internal static string GetResourceName12(short signatureAlgorithm, bool forServer) =>
            FindResourceName12(signatureAlgorithm, forServer) ?? throw new TlsFatalAlert(AlertDescription.internal_error);

        internal static string GetResourceName13(int signatureScheme, bool forServer) =>
            FindResourceName13(signatureScheme, forServer) ?? throw new TlsFatalAlert(AlertDescription.internal_error);

        internal static string FindResourceName12(short signatureAlgorithm, bool forServer)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.dsa:
                return "dsa";
            case SignatureAlgorithm.ecdsa:
                return "ecdsa";
            case SignatureAlgorithm.ed25519:
                return "ed25519";
            case SignatureAlgorithm.ed448:
                return "ed448";
            case SignatureAlgorithm.rsa_pss_pss_sha256:
                return "rsa_pss_256";
            case SignatureAlgorithm.rsa_pss_pss_sha384:
                return "rsa_pss_384";
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return "rsa_pss_512";
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                return forServer ? "rsa-sign" : "rsa";

            // TODO[RFC 9189] Choose names here and apply reverse mappings in GetCACertResource(String)
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:

            default:
                return null;
            }
        }

        internal static string FindResourceName13(int signatureScheme, bool forServer)
        {
            // TODO[tls-slhdsa] Move into switch statement once constants available
            if (SignatureScheme.IsSlhDsa(signatureScheme))
            {
                return SignatureScheme.DRAFT_slhdsa_sha2_128s == signatureScheme ? "slh_dsa_sha2_128s"
                    :  SignatureScheme.DRAFT_slhdsa_sha2_128f == signatureScheme ? "slh_dsa_sha2_128f"
                    :  SignatureScheme.DRAFT_slhdsa_sha2_192s == signatureScheme ? "slh_dsa_sha2_192s"
                    :  SignatureScheme.DRAFT_slhdsa_sha2_192f == signatureScheme ? "slh_dsa_sha2_192f"
                    :  SignatureScheme.DRAFT_slhdsa_sha2_256s == signatureScheme ? "slh_dsa_sha2_256s"
                    :  SignatureScheme.DRAFT_slhdsa_sha2_256f == signatureScheme ? "slh_dsa_sha2_256f"
                    :  SignatureScheme.DRAFT_slhdsa_shake_128s == signatureScheme ? "slh_dsa_shake_128s"
                    :  SignatureScheme.DRAFT_slhdsa_shake_128f == signatureScheme ? "slh_dsa_shake_128f"
                    :  SignatureScheme.DRAFT_slhdsa_shake_192s == signatureScheme ? "slh_dsa_shake_192s"
                    :  SignatureScheme.DRAFT_slhdsa_shake_192f == signatureScheme ? "slh_dsa_shake_192f"
                    :  SignatureScheme.DRAFT_slhdsa_shake_256s == signatureScheme ? "slh_dsa_shake_256s"
                    :  SignatureScheme.DRAFT_slhdsa_shake_256f == signatureScheme ? "slh_dsa_shake_256f"
                    :  throw new InvalidOperationException();
            }

            switch (signatureScheme)
            {
            case SignatureScheme.ecdsa_secp256r1_sha256:
                return "ecdsa";
            case SignatureScheme.ed25519:
                return "ed25519";
            case SignatureScheme.ed448:
                return "ed448";
            case SignatureScheme.rsa_pss_pss_sha256:
                return "rsa_pss_256";
            case SignatureScheme.rsa_pss_pss_sha384:
                return "rsa_pss_384";
            case SignatureScheme.rsa_pss_pss_sha512:
                return "rsa_pss_512";
            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
                return forServer ? "rsa-sign" : "rsa";
            case SignatureScheme.mldsa44:
                return "ml_dsa_44";
            case SignatureScheme.mldsa65:
                return "ml_dsa_65";
            case SignatureScheme.mldsa87:
                return "ml_dsa_87";

            // TODO[tls] Add test resources for these
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
            case SignatureScheme.ecdsa_secp384r1_sha384:
            case SignatureScheme.ecdsa_secp521r1_sha512:

            // TODO[RFC 8998]
            case SignatureScheme.sm2sig_sm3:

            default:
                return null;
            }
        }

        internal static TlsCredentialedAgreement LoadAgreementCredentials(TlsContext context, string[] certResources,
            string keyResource)
        {
            TlsCrypto crypto = context.Crypto;
            Certificate certificate = LoadCertificateChain(context, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedAgreement((BcTlsCrypto)crypto, certificate, privateKey);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static TlsCredentialedDecryptor LoadEncryptionCredentials(TlsContext context, string[] certResources,
            string keyResource)
        {
            TlsCrypto crypto = context.Crypto;
            Certificate certificate = LoadCertificateChain(context, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)crypto, certificate, privateKey);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public static TlsCredentialedSigner LoadSignerCredentials(TlsCryptoParameters cryptoParams, TlsCrypto crypto,
            string[] certResources, string keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            Certificate certificate = LoadCertificateChain(cryptoParams.ServerVersion, crypto, certResources);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
            if (crypto is BcTlsCrypto)
            {
                AsymmetricKeyParameter privateKey = LoadBcPrivateKeyResource(keyResource);

                return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)crypto, privateKey, certificate, signatureAndHashAlgorithm);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static TlsCredentialedSigner LoadSignerCredentials(TlsContext context, string[] certResources,
            string keyResource, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            TlsCrypto crypto = context.Crypto;
            TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);

            return LoadSignerCredentials(cryptoParams, crypto, certResources, keyResource, signatureAndHashAlgorithm);
        }

        internal static TlsCredentialedSigner LoadSignerCredentials(TlsContext context,
            IList<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm,
            string certResource, string keyResource)
        {
            if (supportedSignatureAlgorithms == null)
            {
                supportedSignatureAlgorithms = TlsUtilities.GetDefaultSignatureAlgorithms(signatureAlgorithm);
            }

            SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

            foreach (SignatureAndHashAlgorithm alg in supportedSignatureAlgorithms)
            {
                if (alg.Signature == signatureAlgorithm)
                {
                    // Just grab the first one we find
                    signatureAndHashAlgorithm = alg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
                return null;

            return LoadSignerCredentials(context, new string[]{ certResource }, keyResource,
                signatureAndHashAlgorithm);
        }

        internal static TlsCredentialedSigner LoadSignerCredentialsServer(TlsContext context,
            IList<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, short signatureAlgorithm)
        {
            string sigName = GetResourceName12(signatureAlgorithm, forServer: true);

            string certResource = "x509-server-" + sigName + ".pem";
            string keyResource = "x509-server-key-" + sigName + ".pem";

            return LoadSignerCredentials(context, supportedSignatureAlgorithms, signatureAlgorithm, certResource,
                keyResource);
        }

        /// <summary>
        /// Build a fresh Ed25519 raw public key (RFC 7250) signer credential for the connection's crypto backend.
        /// </summary>
        /// <exception cref="IOException"/>
        internal static TlsCredentialedSigner CreateRawKeyEd25519Credentials(TlsContext context)
        {
            TlsCrypto crypto = context.Crypto;
            byte[] certificateRequestContext = TlsUtilities.IsTlsV13(context) ? TlsUtilities.EmptyBytes : null;

            if (crypto is BcTlsCrypto bcCrypto)
            {
                Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(bcCrypto.SecureRandom);
                TlsCertificate rawKeyCert = new BcTlsRawKeyCertificate(bcCrypto,
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(privateKey.GeneratePublicKey()));
                Certificate certificate = new Certificate(CertificateType.RawPublicKey, certificateRequestContext,
                    new CertificateEntry[]{ new CertificateEntry(rawKeyCert, null) });

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), bcCrypto, privateKey,
                    certificate, SignatureAndHashAlgorithm.ed25519);
            }
            else
            {
                // bc-java supports also JcaTlsCrypto here
                throw new InvalidOperationException();
            }
        }

        internal static Certificate LoadCertificateChain(ProtocolVersion protocolVersion, TlsCrypto crypto,
            string[] resources)
        {
            if (TlsUtilities.IsTlsV13(protocolVersion))
            {
                CertificateEntry[] certificateEntryList = new CertificateEntry[resources.Length];
                for (int i = 0; i < resources.Length; ++i)
                {
                    TlsCertificate certificate = LoadCertificateResource(crypto, resources[i]);

                    // TODO[tls13] Add possibility of specifying e.g. CertificateStatus
                    IDictionary<int, byte[]> extensions = null;

                    certificateEntryList[i] = new CertificateEntry(certificate, extensions);
                }

                // TODO[tls13] Support for non-empty request context
                byte[] certificateRequestContext = TlsUtilities.EmptyBytes;

                return new Certificate(certificateRequestContext, certificateEntryList);
            }
            else
            {
                TlsCertificate[] chain = new TlsCertificate[resources.Length];
                for (int i = 0; i < resources.Length; ++i)
                {
                    chain[i] = LoadCertificateResource(crypto, resources[i]);
                }
                return new Certificate(chain);
            }
        }

        internal static Certificate LoadCertificateChain(TlsContext context, string[] resources)
        {
            return LoadCertificateChain(context.ServerVersion, context.Crypto, resources);
        }

        internal static X509CertificateStructure LoadBcCertificateResource(string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.EndsWith("CERTIFICATE"))
            {
                return X509CertificateStructure.GetInstance(pem.Content);
            }
            throw new ArgumentException("doesn't specify a valid certificate", nameof(resource));
        }

        internal static TlsCertificate LoadCertificateResource(TlsCrypto crypto, string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.EndsWith("CERTIFICATE"))
            {
                return crypto.CreateCertificate(pem.Content);
            }
            throw new ArgumentException("doesn't specify a valid certificate", nameof(resource));
        }

        internal static AsymmetricKeyParameter LoadBcPrivateKeyResource(string resource)
        {
            PemObject pem = LoadPemResource(resource);
            if (pem.Type.Equals("PRIVATE KEY"))
            {
                return PrivateKeyFactory.CreateKey(pem.Content);
            }
            if (pem.Type.Equals("ENCRYPTED PRIVATE KEY"))
            {
                throw new NotSupportedException("Encrypted PKCS#8 keys not supported");
            }
            if (pem.Type.Equals("RSA PRIVATE KEY"))
            {
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
                return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                    rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                    rsa.Exponent2, rsa.Coefficient);
            }
            if (pem.Type.Equals("EC PRIVATE KEY"))
            {
                ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(pem.Content);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.Parameters);
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
                return PrivateKeyFactory.CreateKey(privInfo);
            }
            throw new ArgumentException("doesn't specify a valid private key", nameof(resource));
        }

        internal static PemObject LoadPemResource(string resource)
        {
            return PemObjectCache.GetOrAdd(resource, key =>
            {
                using (var p = new PemReader(new StreamReader(SimpleTest.FindTestResource("tls", "credentials", key))))
                {
                    return p.ReadPemObject();
                }
            });
        }

        internal static bool AreSameCertificate(TlsCrypto crypto, TlsCertificate cert, string resource)
        {
            // TODO Cache test resources?
            return AreSameCertificate(cert, LoadCertificateResource(crypto, resource));
        }

        internal static bool AreSameCertificate(TlsCertificate a, TlsCertificate b)
        {
            // TODO[tls-ops] Support equals on TlsCertificate?
            return Arrays.AreEqual(a.GetEncoded(), b.GetEncoded());
        }

        internal static TlsCertificate[] GetTrustedCertPath(TlsCrypto crypto, TlsCertificate cert, string[] resources)
        {
            foreach (string eeCertResource in resources)
            {
                TlsCertificate eeCert = LoadCertificateResource(crypto, eeCertResource);
                if (AreSameCertificate(cert, eeCert))
                {
                    string caCertResource = GetCACertResource(eeCertResource);
                    TlsCertificate caCert = LoadCertificateResource(crypto, caCertResource);
                    if (null != caCert)
                    {
                        return new TlsCertificate[]{ eeCert, caCert };
                    }
                }
            }
            return null;
        }
    }
}
