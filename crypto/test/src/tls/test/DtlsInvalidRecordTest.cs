using System;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// RFC 9147 4.5.2 / RFC 6347 4.1.2.7: invalid DTLS records SHOULD be silently discarded, preserving the
    /// association. A forged record whose body is too short for the cipher (decode_error), or not a whole number
    /// of blocks (decryption_failed), must be dropped just like one whose MAC fails (bad_record_mac), rather than
    /// tearing the connection down with a fatal alert. This test establishes a loopback DTLS association, injects
    /// such records from off-path towards each peer, and checks that application data still flows.
    /// </summary>
    [TestFixture]
    public class DtlsInvalidRecordTest
    {
        private const int RecordHeaderLength = 13;

        [Test]
        public void AeadCipherInvalidRecordsDiscarded()
        {
            /*
             * ChaCha20-Poly1305: 16 byte tag, no explicit nonce. A 2 byte body is below the decode limit
             * (decode_error); a 40 byte body reaches the AEAD, whose tag check fails (bad_record_mac).
             */
            ImplInvalidRecordsDiscarded(CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
                new int[]{ 2, 40 });
        }

        [Test]
        public void BlockCipherInvalidRecordsDiscarded()
        {
            /*
             * AES-128-CBC with HMAC-SHA256: 16 byte explicit IV, 16 byte blocks, 32 byte MAC. A 2 byte body is
             * below the minimum length (decode_error); 65 bytes is above the minimum but not a whole number of
             * blocks, with or without encrypt-then-MAC (decryption_failed); 80 bytes decrypts and then fails the
             * MAC or padding check (bad_record_mac).
             */
            ImplInvalidRecordsDiscarded(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
                new int[]{ 2, 65, 80 });
        }

        private static void ImplInvalidRecordsDiscarded(int cipherSuite, int[] forgedBodyLengths)
        {
            var client = new SingleSuitePskDtlsClient(cipherSuite);
            var server = new MockPskDtlsServer();

            var clientProtocol = new DtlsClientProtocol();
            var serverProtocol = new DtlsServerProtocol();

            var network = new MockDatagramAssociation(1500);

            // Keep the raw transports: sending on one delivers a datagram to the other peer's receive queue.
            DatagramTransport clientTransport = network.Client;
            DatagramTransport serverTransport = network.Server;

            var serverTask = new ServerTask(serverProtocol, server, serverTransport);

            var serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

            SecureRandom random = client.Crypto.SecureRandom;

            try
            {
                // Confirm the association is up and carrying application data.
                ImplEcho(dtlsClient, 1);

                // A sequence number well ahead of the replay window, so that each forgery is "fresh".
                long forgedSeq = 1L << 40;

                for (int i = 0; i < forgedBodyLengths.Length; ++i)
                {
                    int bodyLength = forgedBodyLengths[i];

                    // Off-path forgery towards the server (delivered by sending on the client's raw transport).
                    byte[] toServer = CreateForgedRecord(random, forgedSeq++, bodyLength);
                    clientTransport.Send(toServer, 0, toServer.Length);

                    // Off-path forgery towards the client.
                    byte[] toClient = CreateForgedRecord(random, forgedSeq++, bodyLength);
                    serverTransport.Send(toClient, 0, toClient.Length);

                    // Both peers must have discarded the forgery and still be able to exchange application data.
                    ImplEcho(dtlsClient, i + 2);
                }
            }
            finally
            {
                dtlsClient.Close();
                serverTask.Shutdown(serverThread);
            }

            Assert.IsNull(serverTask.Failure, "Server failed after forged record: " + serverTask.Failure);
        }

        private static byte[] CreateForgedRecord(SecureRandom random, long seq, int bodyLength)
        {
            byte[] record = new byte[RecordHeaderLength + bodyLength];
            record[0] = (byte)ContentType.application_data;
            TlsUtilities.WriteVersion(ProtocolVersion.DTLSv12, record, 1);
            TlsUtilities.WriteUint16(1, record, 3);
            TlsUtilities.WriteUint48(seq, record, 5);
            TlsUtilities.WriteUint16(bodyLength, record, 11);
            random.NextBytes(record, RecordHeaderLength, bodyLength);
            return record;
        }

        private static void ImplEcho(DtlsTransport dtlsClient, int length)
        {
            byte[] data = new byte[length];
            Arrays.Fill(data, (byte)length);
            dtlsClient.Send(data, 0, data.Length);

            byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
            for (int attempt = 0; attempt < 10; ++attempt)
            {
                int received = dtlsClient.Receive(buf, 0, buf.Length, 500);
                if (received >= 0)
                {
                    Assert.IsTrue(Arrays.AreEqual(data, 0, data.Length, buf, 0, received), "Echo mismatch");
                    return;
                }
            }
            Assert.Fail("No echo received from server");
        }

        private sealed class SingleSuitePskDtlsClient
            : MockPskDtlsClient
        {
            private readonly int m_cipherSuite;

            internal SingleSuitePskDtlsClient(int cipherSuite)
                : base(null)
            {
                m_cipherSuite = cipherSuite;
            }

            protected override int[] GetSupportedCipherSuites() =>
                TlsUtilities.GetSupportedCipherSuites(Crypto, new int[]{ m_cipherSuite });
        }

        private sealed class ServerTask
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly DatagramTransport m_serverTransport;
            private volatile bool m_isShutdown = false;
            private volatile Exception m_failure = null;

            internal ServerTask(DtlsServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
                m_serverTransport = serverTransport;
            }

            internal Exception Failure => m_failure;

            public void Run()
            {
                try
                {
                    DtlsTransport dtlsServer = m_serverProtocol.Accept(m_server, m_serverTransport);
                    byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsServer.Receive(buf, 0, buf.Length, 100);
                        if (length >= 0)
                        {
                            dtlsServer.Send(buf, 0, length);
                        }
                    }
                    dtlsServer.Close();
                }
                catch (Exception e)
                {
                    m_failure = e;
                    Console.Error.WriteLine(e);
                    Console.Error.Flush();
                }
            }

            internal void Shutdown(Thread serverThread)
            {
                if (!m_isShutdown)
                {
                    m_isShutdown = true;
                    serverThread.Join();
                }
            }
        }
    }
}
