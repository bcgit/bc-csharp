using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockSrpTlsClient
        : SrpTlsClient
    {
        internal TlsSession m_session;

        internal MockSrpTlsClient(TlsSession session, TlsSrpIdentity srpIdentity)
            : base(new BcTlsCrypto(new SecureRandom()), srpIdentity)
        {
            this.m_session = session;
        }

        protected override IList<ProtocolName> GetProtocolNames()
        {
            var protocolNames = new List<ProtocolName>();
            protocolNames.Add(ProtocolName.Http_1_1);
            protocolNames.Add(ProtocolName.Http_2_Tls);
            return protocolNames;
        }

        public override TlsSession GetSessionToResume()
        {
            return m_session;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS-SRP client raised alert: " + AlertLevel.GetText(alertLevel)
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
            output.WriteLine("TLS-SRP client received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());

            {
                /*
                 * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
                 */
                TlsExtensionsUtilities.AddMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
                TlsExtensionsUtilities.AddPaddingExtension(clientExtensions, m_context.Crypto.SecureRandom.Next(16));
                TlsExtensionsUtilities.AddTruncatedHmacExtension(clientExtensions);
            }
            return clientExtensions;
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            Console.WriteLine("TLS-SRP client negotiated " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new MyTlsAuthentication(m_context);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Client ALPN: " + protocolName.GetUtf8Decoding());
            }

            TlsSession newSession = m_context.Session;
            if (newSession != null)
            {
                if (newSession.IsResumable)
                {
                    byte[] newSessionID = newSession.SessionID;
                    string hex = ToHexString(newSessionID);

                    if (m_session != null && Arrays.AreEqual(m_session.SessionID, newSessionID))
                    {
                        Console.WriteLine("Client resumed session: " + hex);
                    }
                    else
                    {
                        Console.WriteLine("Client established session: " + hex);
                    }

                    this.m_session = newSession;
                }

                byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
                if (null != tlsServerEndPoint)
                {
                    Console.WriteLine("Client 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));
                }

                byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
                Console.WriteLine("Client 'tls-unique': " + ToHexString(tlsUnique));
            }
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv12.Only();
        }

        internal class MyTlsAuthentication
            : ServerOnlyTlsAuthentication
        {
            private readonly TlsContext m_context;

            internal MyTlsAuthentication(TlsContext context)
            {
                this.m_context = context;
            }

            public override void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();

                Console.WriteLine("TLS-SRP client received server certificate chain of length " + chain.Length);
                for (int i = 0; i != chain.Length; i++)
                {
                    X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtilities.Fingerprint(entry) + " ("
                        + entry.Subject + ")");
                }

                bool isEmpty = serverCertificate == null || serverCertificate.Certificate == null
                    || serverCertificate.Certificate.IsEmpty;

                if (isEmpty)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                string[] trustedCertResources = new string[] { "x509-server-dsa.pem", "x509-server-rsa_pss_256.pem",
                    "x509-server-rsa_pss_384.pem", "x509-server-rsa_pss_512.pem", "x509-server-rsa-sign.pem" };

                TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0],
                    trustedCertResources);

                if (null == certPath)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
            }
        };
    }
}
