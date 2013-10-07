using NUnit.Framework;
using System.Threading;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Tls;
using System;
using crypto.test.src.util.io;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities;
using System.Diagnostics;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    [TestFixture]
    public class TLSProtocolTest : SimpleTest
    {
        private static byte[] TestData = new byte[1024 * 1024 * 10];
        private static int TimesToSendTestData = 10;


        private CipherSuite[] cipherSuites = new CipherSuite[]{
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
                                        CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,                                        
                                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
                                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,};        

        private SecureRandom secureRandom = new SecureRandom();

        [Test]
        public void TestTlsProtocol()
        {
            TestTlsCipherSuite(cipherSuites, true);

            foreach (var suite in cipherSuites)
            {
                TestTlsCipherSuite(new CipherSuite[] { suite }, true);
            }
        }

        [Test]
        public void TestTlsProtocol1()
        {
            TestTlsCipherSuite(cipherSuites, false);

            foreach (var suite in cipherSuites)
            {
                TestTlsCipherSuite(new CipherSuite[] { suite }, false);
            }
        }

        private void TestTlsCipherSuite(CipherSuite[] cipherSuites, bool clientAuthentcation)
        {
            var stopwatch = new Stopwatch();

            var clientRead = new PipedStream();
            var serverRead = new PipedStream();
            var clientWrite = serverRead;
            var serverWrite = clientRead;

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

            var server = new MyTlsServer()
            {
                ClientAuthentication = clientAuthentcation
            };

            ServerThread serverThread = new ServerThread(serverProtocol, server);
            serverThread.Start();

            MyTlsClient client = new MyTlsClient(cipherSuites);

            stopwatch.Start();
            clientProtocol.Connect(client);
            secureRandom.NextBytes(TestData);

            var output = clientProtocol.Stream;

            for (int i = 0; i < TimesToSendTestData; i++)
            {
                output.Write(TestData, 0, TestData.Length);
            }

            byte[] echo = new byte[TestData.Length];

            for (int i = 0; i < TimesToSendTestData; i++)
            {
                Streams.ReadFully(clientProtocol.Stream, echo);
            }
            
            stopwatch.Stop();

            serverThread.Join();

            clientProtocol.Close();

            if (!Arrays.AreEqual(TestData, echo))
            {
                this.Fail("Roundtrip data does not match");              
            }

            Console.WriteLine();

            foreach (var cipher in cipherSuites)
            {
                Console.WriteLine(cipher);
            }


            Console.WriteLine();
            Console.WriteLine("Test lasted: {0} ms", stopwatch.ElapsedMilliseconds);
            Console.WriteLine();
        }

        class ServerThread
        {
            private TlsServerProtocol serverProtocol;
            private MyTlsServer _server;
            private Thread _thread;

            public ServerThread(TlsServerProtocol serverProtocol, MyTlsServer server)
            {
                this.serverProtocol = serverProtocol;
                _thread = new Thread(Run);
                _server = server;
            }

            public void Start()
            {
                _thread.Start();
            }

            public void Run()
            {                
                serverProtocol.Accept(_server);
                var payload = new byte[TestData.Length];

                for (int i = 0; i < TimesToSendTestData; i++)
                {
                    var bytesRead = Streams.ReadFully(serverProtocol.Stream, payload);                    
                }

                for (int i = 0; i < TimesToSendTestData; i++)
                {
                    serverProtocol.Stream.Write(payload, 0, payload.Length);
                }
            }

            public void Join()
            {
                _thread.Join();
            }
        }

        class MyTlsClient : DefaultTlsClient
        {
            private CipherSuite[] cipherSuites;

            public MyTlsClient(CipherSuite[] cipherSuite)
            {
                this.cipherSuites = cipherSuite;
            }

            public override CipherSuite[] GetCipherSuites()
            {
                return cipherSuites;
            }

            public override void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, string message, Exception cause)
            {
                Console.WriteLine("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
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
                Console.WriteLine("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
                    + alertDescription + ")");
            }

            public override TlsAuthentication GetAuthentication()
            {
                return new TlsAuthenticationImpl(this);
            }

            class TlsAuthenticationImpl : TlsAuthentication
            {
                private MyTlsClient outer;

                public TlsAuthenticationImpl(MyTlsClient outer)
                {
                    this.outer = outer;
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
                        Console.WriteLine(" Subject:  (" + entry.Subject + ")");
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
                                return TlsTestUtils.loadSignerCredentials(outer.context, new String[]{"crypto.test.resources.x509-server.pem",
                                    "crypto.test.resources.x509-ca.pem"}, "crypto.test.resources.x509-server-key.pem");
                            }
                        }
                    }
                    return null;
                }

                #endregion
            }
        }

        class MyTlsServer : DefaultTlsServer
        {
            public bool ClientAuthentication
            {
                get;
                set;
            }

            public override void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, string message, Exception cause)
            {
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
                Console.WriteLine("TLS server received alert (AlertLevel." + alertLevel + ", AlertDescription."
                    + alertDescription + ")");
            }


            public override CertificateRequest GetCertificateRequest()
            {
                if (ClientAuthentication)
                {
                    return new CertificateRequest(new ClientCertificateType[] { ClientCertificateType.rsa_sign }, null, null);
                }
                else
                    return base.GetCertificateRequest();
            }

            public override void NotifyClientCertificate(Certificate clientCertificate)
            {
                var chain = clientCertificate.GetCerts();
                System.Console.WriteLine("Received client certificate chain of length " + chain.Length);
                for (int i = 0; i != chain.Length; i++)
                {
                    var entry = chain[i];
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.Subject + ")");
                }
            }

            protected override TlsEncryptionCredentials GetRSAEncryptionCredentials()
            {
                return TlsTestUtils.loadEncryptionCredentials(context, new string[] { "crypto.test.resources.x509-server.pem", "crypto.test.resources.x509-ca.pem" },
                    "crypto.test.resources.x509-server-key.pem");
            }

            protected override TlsSignerCredentials GetRSASignerCredentials()
            {
                return TlsTestUtils.loadSignerCredentials(context, new string[] { "crypto.test.resources.x509-server.pem", "crypto.test.resources.x509-ca.pem" },
                    "crypto.test.resources.x509-server-key.pem");
            }
        }
     

        public override void PerformTest()
        {
            TestTlsProtocol();
            TestTlsProtocol1();
        }

        public override string Name
        {
            get { return "TlsProtocolTest"; }
        }
    }
}