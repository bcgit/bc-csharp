using System;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Utilities;
using System.Xml;


namespace Org.BouncyCastle.Crypto.Tls.Test
{

    public class MockDTLSClient : DefaultTlsClient
    {
        protected TlsSession session;

        public MockDTLSClient(TlsSession session)
        {
            this.session = session;
        }

        public override TlsSession SessionToResume
        {
            get
            {
                return this.session;
            }
        }

        public override void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, string message, Exception cause)
        {
            Console.Write("DTLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");

            if (message != null)
            {
                Console.WriteLine(message);
            }
            if (cause != null)
            {
                Console.WriteLine(cause.StackTrace);
            }
        }

        public override void NotifyAlertReceived(AlertLevel alertLevel, AlertDescription alertDescription)
        {
            Console.WriteLine("DTLS client received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription + ")");
        }

        public override ProtocolVersion ClientVersion
        {
            get
            {
                return ProtocolVersion.DTLSv10;
            }
        }

        public override ProtocolVersion MinimumVersion
        {
            get
            {
                return ProtocolVersion.DTLSv10;
            }
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new TlsAuthenticationImpl(this);
        }

        private class TlsAuthenticationImpl : TlsAuthentication
        {
            private readonly MockDTLSClient _outer;

            public TlsAuthenticationImpl(MockDTLSClient outer)
            {
                _outer = outer;
            }

            #region TlsAuthentication Members

            public void NotifyServerCertificate(Certificate serverCertificate)
            {
                var chain = serverCertificate.GetCerts();
                Console.WriteLine("Received server certificate chain of length " + chain.Length);
                for (int i = 0; i != chain.Length; i++)
                {
                    var entry = chain[i];
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.Subject + ")");
                }
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                var certificateTypes = certificateRequest.CertificateTypes;
                if (certificateTypes != null)
                {
                    for (int i = 0; i < certificateTypes.Length; ++i)
                    {
                        if (certificateTypes[i] == ClientCertificateType.rsa_sign)
                        {
                            // TODO Create a distinct client certificate for use here
                            return TlsTestUtils.loadSignerCredentials(_outer.context, new String[] { "crypto.test.resources.x509-server.pem", 
                                "crypto.test.resources.x509-ca.pem" }, "crypto.test.resources.x509-server-key.pem");
                        }
                    }
                }
                return null;
            }

            #endregion
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsSession newSession = context.ResumableSession;

            if (newSession != null)
            {
                byte[] newSessionID = newSession.GetSessionID();
                String hex = Convert.ToBase64String(newSessionID);

                if (this.session != null && Arrays.AreEqual(this.session.GetSessionID(), newSessionID))
                {
                    Console.WriteLine("Resumed session: " + hex);
                }
                else
                {
                    Console.WriteLine("Established session: " + hex);
                }

                this.session = newSession;
            }
        }
    }
}