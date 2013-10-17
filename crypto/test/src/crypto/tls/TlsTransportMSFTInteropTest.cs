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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    [TestFixture]
    public class TLSProtocolMSFTInteropTest : SimpleTest
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

            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

            var server = new MyTlsServer()
            {
                ClientAuthentication = clientAuthentcation
            };

            ServerThread serverThread = new ServerThread(serverProtocol, server);
            serverThread.Start();

            SslStream client = new SslStream(new DualStream(clientRead, clientWrite), false, (sender, cert, chain, policyErrors) => 
            {
                return true;
            });            

            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            store.Open(OpenFlags.ReadOnly);

            X509Certificate certificate = null;

            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            foreach (var storedCertificate in storecollection)
            {
                if (storedCertificate.Subject == "CN=localhost")
                {
                    certificate = storedCertificate;
                    break;
                }
            }

            var blob = certificate.Export(X509ContentType.Pkcs12, "password");
            server.SetCertificate(new MemoryStream(blob), "password".ToCharArray());

            secureRandom.NextBytes(TestData);

            stopwatch.Start();

            client.AuthenticateAsClient("localhost", new X509CertificateCollection( new X509Certificate[] { certificate } ), SslProtocols.Tls, false);            

            for (int i = 0; i < TimesToSendTestData; i++)
            {
                client.Write(TestData, 0, TestData.Length);
            }

            byte[] echo = new byte[TestData.Length];

            for (int i = 0; i < TimesToSendTestData; i++)
            {
                Streams.ReadFully(client, echo);
            }
            
            stopwatch.Stop();

            serverThread.Join();

            client.Close();

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

        class MyTlsServer : DefaultTlsServer
        {
            private Certificate _certificate;
            private AsymmetricKeyParameter _privateKey;

            public void SetCertificate(Stream pkcs12, char[] password)
            {
                Pkcs12Store store = new Pkcs12Store(pkcs12, password);

                foreach (string alias in store.Aliases)
                {
                    // alias is not specified we just load the first certificate
                    if (store.IsCertificateEntry(alias))
                    {
                        _certificate = LoadCertificate(store, alias);
                    }

                    if (store.IsKeyEntry(alias))
                    {
                        _privateKey = store.GetKey(alias).Key;
                    }
                }
            }

            private void LoadCertificate(Pkcs12Store store, string alias, string keyAlias)
            {
                _certificate = LoadCertificate(store, alias);
                _privateKey = store.GetKey(keyAlias).Key;
            }

            private Certificate LoadCertificate(Pkcs12Store store, string alias)
            {
                X509CertificateEntry[] entries = store.GetCertificateChain(alias);

                if (entries == null)
                {
                    entries = new X509CertificateEntry[] { store.GetCertificate(alias) };
                    if (entries[0] == null)
                        throw new CryptoException("Failed load crtificate with from the PCKS12 store.");
                }

                X509CertificateStructure[] certChain = new X509CertificateStructure[entries.Length];
                for (int i = 0; i < entries.Length; i++)
                    certChain[i] = entries[i].Certificate.CertificateStructure;

                return new Certificate(certChain);
            }
                       
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
                return new DefaultTlsEncryptionCredentials(this.context, _certificate, _privateKey);
            }

            protected override TlsSignerCredentials GetRSASignerCredentials()
            {
                return new DefaultTlsSignerCredentials(this.context, _certificate, _privateKey);
            }
        }
     
        public override void PerformTest()
        {
            TestTlsProtocol();
            TestTlsProtocol1();
        }

        public override string Name
        {
            get { return "TlsProtocolMSFTInteropTest"; }
        }
    }
}