﻿using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockDtlsServer
        : DefaultTlsServer
    {
        internal MockDtlsServer()
            : this(new BcTlsCrypto())
        {
        }

        internal MockDtlsServer(TlsCrypto crypto)
            : base(crypto)
        {
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS server raised alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("DTLS server received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            Console.WriteLine("DTLS server negotiated " + serverVersion);

            return serverVersion;
        }

        public override CertificateRequest GetCertificateRequest()
        {
            short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
                ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(m_context.ServerVersion))
            {
                serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
            }

            var certificateAuthorities = new List<X509Name>();
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-dsa.pem").Subject);
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-ecdsa.pem").Subject);
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-rsa.pem").Subject);

            // All the CA certificates are currently configured with this subject
            certificateAuthorities.Add(new X509Name("CN=BouncyCastle TLS Test CA"));

            return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            TlsCertificate[] chain = clientCertificate.GetCertificateList();

            Console.WriteLine("DTLS server received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtilities.Fingerprint(entry) + " ("
                    + entry.Subject + ")");
            }

            bool isEmpty = (clientCertificate == null || clientCertificate.IsEmpty);

            if (isEmpty)
                return;

            string[] trustedCertResources = new string[]{ "x509-client-dsa.pem", "x509-client-ecdh.pem",
                "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem",
                "x509-client-rsa_pss_256.pem", "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",
                "x509-client-rsa.pem" };

            TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0],
                trustedCertResources);

            if (null == certPath)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Server ALPN: " + protocolName.GetUtf8Decoding());
            }

            byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            Console.WriteLine("Server 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));

            byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
            Console.WriteLine("Server 'tls-unique': " + ToHexString(tlsUnique));
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            return TlsTestUtilities.LoadEncryptionCredentials(m_context,
                new string[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" }, "x509-server-key-rsa-enc.pem");
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, clientSigAlgs, SignatureAlgorithm.rsa);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.DTLSv12.Only();
        }
    }
}
