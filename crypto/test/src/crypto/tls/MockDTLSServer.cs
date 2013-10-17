using System;
namespace Org.BouncyCastle.Crypto.Tls.Test
{
    public class MockDTLSServer : DefaultTlsServer
    {
        public override void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, string message, Exception cause)
        {            
            Console.WriteLine("DTLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
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
            Console.WriteLine("DTLS server received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
        }

        public override CertificateRequest GetCertificateRequest()
        {            
            return new CertificateRequest(new ClientCertificateType[] { ClientCertificateType.rsa_sign }, null, null);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {            
            var chain = clientCertificate.GetCerts();
            System.Console.WriteLine("Received client certificate chain of length " + chain.Length);
            for (int i = 0; i != chain.Length; i++)
            {
                var entry = chain[i];
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.Subject+ ")");
            }
        }

        protected override ProtocolVersion MaximumVersion
        {
            get
            {
                return ProtocolVersion.DTLSv10;
            }
        }

        protected override ProtocolVersion MinimumVersion
        {
            get
            {
                return ProtocolVersion.DTLSv10;
            }
        }

        protected override TlsEncryptionCredentials GetRSAEncryptionCredentials()
        {
            return TlsTestUtils.loadEncryptionCredentials(context, new String[] { "crypto.test.resources.x509-server.pem", 
                "crypto.test.resources.x509-ca.pem" }, "crypto.test.resources.x509-server-key.pem");
        }
        
        protected override TlsSignerCredentials GetRSASignerCredentials()
        {
            return TlsTestUtils.loadSignerCredentials(context, new String[] { "crypto.test.resources.x509-server.pem",
                "crypto.test.resources.x509-ca.pem" }, "crypto.test.resources.x509-server-key.pem");
        }
    }
}