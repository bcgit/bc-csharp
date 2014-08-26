using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls.Tests
{
    internal class MockTlsServer
        :   DefaultTlsServer
    {
        public override void NotifyAlertRaised(byte alertLevel, byte alertDescription, string message, Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(byte alertLevel, byte alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        protected override int[] GetCipherSuites()
        {
            return Arrays.Concatenate(base.GetCipherSuites(),
                new int[]
                {
                    CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1,
                    CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1,
                    CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1,
                    CipherSuite.TLS_RSA_WITH_SALSA20_SHA1,
                });
        }

        protected override ProtocolVersion MaximumVersion
        {
            get { return ProtocolVersion.TLSv12; }
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            Console.WriteLine("TLS server negotiated " + serverVersion);

            return serverVersion;
        }

        public override CertificateRequest GetCertificateRequest()
        {
            IList serverSigAlgs = null;

            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(mServerVersion))
            {
                byte[] hashAlgorithms = new byte[]{ HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256,
                    HashAlgorithm.sha224, HashAlgorithm.sha1 };
                byte[] signatureAlgorithms = new byte[]{ SignatureAlgorithm.rsa };

                serverSigAlgs = new ArrayList();
                for (int i = 0; i < hashAlgorithms.Length; ++i)
                {
                    for (int j = 0; j < signatureAlgorithms.Length; ++j)
                    {
                        serverSigAlgs.Add(new SignatureAndHashAlgorithm(hashAlgorithms[i],
                            signatureAlgorithms[j]));
                    }
                }
            }

            IList certificateAuthorities = new ArrayList();
            certificateAuthorities.Add(TlsTestUtilities.LoadCertificateResource("x509-ca.pem").Subject);

            return new CertificateRequest(new byte[]{ ClientCertificateType.rsa_sign }, serverSigAlgs, certificateAuthorities);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            X509CertificateStructure[] chain = clientCertificate.GetCertificateList();
            Console.WriteLine("TLS server received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                X509CertificateStructure entry = chain[i];
                // TODO Create fingerprint based on certificate signature algorithm digest
                Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtilities.Fingerprint(entry) + " ("
                    + entry.Subject + ")");
            }
        }

        protected override TlsEncryptionCredentials GetRsaEncryptionCredentials()
        {
            return TlsTestUtilities.LoadEncryptionCredentials(mContext, new string[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem");
        }

        protected override TlsSignerCredentials GetRsaSignerCredentials()
        {
            /*
             * TODO Note that this code fails to provide default value for the client supported
             * algorithms if it wasn't sent.
             */
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
            IList sigAlgs = mSupportedSignatureAlgorithms;
            if (sigAlgs != null)
            {
                foreach (SignatureAndHashAlgorithm sigAlg in sigAlgs)
                {
                    if (sigAlg.Signature == SignatureAlgorithm.rsa)
                    {
                        signatureAndHashAlgorithm = sigAlg;
                        break;
                    }
                }

                if (signatureAndHashAlgorithm == null)
                {
                    return null;
                }
            }

            return TlsTestUtilities.LoadSignerCredentials(mContext, new string[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem", signatureAndHashAlgorithm);
        }
    }
}
