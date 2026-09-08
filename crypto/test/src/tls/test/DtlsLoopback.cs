using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    internal sealed class DtlsLoopbackOptions
    {
        internal int Mtu = 1500;

        /// <summary>Have the server require a HelloVerifyRequest cookie exchange (via <see cref="DtlsVerifier"/>)
        /// before it accepts the handshake.</summary>
        internal bool UseCookieExchange = false;

        /// <summary>Percentage of datagrams the client's transport loses, in each direction, while the handshake
        /// is in progress, to exercise handshake retransmission. The transport becomes reliable once the client's
        /// handshake completes, since application data is never retransmitted, or once
        /// <see cref="TlsTestConfig.DtlsMaxDroppedDatagrams"/> have been lost in a direction, which bounds the run.
        /// </summary>
        internal int HandshakePacketLossPercent = 0;

        /// <summary>Wraps the client's transport, e.g. to drop or aggregate datagrams; null for none. Applied
        /// on top of any <see cref="HandshakePacketLossPercent"/>.</summary>
        internal Func<DatagramTransport, DatagramTransport> ClientTransportDecorator = null;

        /// <summary>What the client does once connected, or null to <see cref="DtlsLoopback.Echo"/> datagrams of
        /// sizes 1 to 10. The association is passed so that a body can inject datagrams on the raw transports.
        /// </summary>
        internal Action<DtlsTransport, MockDatagramAssociation> ClientBody = null;
    }

    /// <summary>Runs a DTLS client and server against each other over an in-memory datagram association.</summary>
    /// <remarks>
    /// The server runs on its own thread and echoes application data until told to stop. The client, on the calling
    /// thread, connects and runs the client body. Whatever either end throws is captured into the
    /// <see cref="LoopbackResult"/> rather than propagated, so the caller decides which failures are expected. A
    /// server that does not stop by itself (typically one still waiting in Accept for a client that has given up)
    /// is cancelled, so a failure at one end cannot hang the run.
    /// </remarks>
    internal static class DtlsLoopback
    {
        private const int EchoAttempts = 10;
        private const int EchoWaitMillis = 500;
        private const int GraceMillis = 2000;
        private const int HandshakeDeadlineMillis = 60000;
        private const int JoinTimeoutMillis = 30000;
        private const int ServerPollMillis = 100;

        internal static LoopbackResult Run(TlsClient client, TlsServer server) => Run(client, server, null, null);

        internal static LoopbackResult Run(TlsClient client, TlsServer server, DtlsLoopbackOptions options) =>
            Run(client, server, options, null);

        /// <param name="clientProtocolFactory">Creates the client protocol, or null for a plain
        /// <see cref="DtlsClientProtocol"/>.</param>
        internal static LoopbackResult Run(TlsClient client, TlsServer server, DtlsLoopbackOptions options,
            Func<DtlsClientProtocol> clientProtocolFactory)
        {
            options = options ?? new DtlsLoopbackOptions();

            DtlsClientProtocol clientProtocol = clientProtocolFactory == null
                ?   new DtlsClientProtocol()
                :   clientProtocolFactory();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(options.Mtu);

            DatagramTransport clientTransport = network.Client;
            UnreliableDatagramTransport lossyTransport = null;
            if (options.HandshakePacketLossPercent > 0)
            {
                int loss = options.HandshakePacketLossPercent, maxDropped = TlsTestConfig.DtlsMaxDroppedDatagrams;
                lossyTransport = new UnreliableDatagramTransport(clientTransport, client.Crypto.SecureRandom, loss,
                    loss, maxDropped, maxDropped);
                clientTransport = lossyTransport;
            }
            if (options.ClientTransportDecorator != null)
            {
                clientTransport = options.ClientTransportDecorator(clientTransport);
            }
            if (TlsTestConfig.Debug)
            {
                clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);
            }

            ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server, options.UseCookieExchange);
            ClientTransportGuard guard = new ClientTransportGuard(clientTransport, lossyTransport, serverTask);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            LoopbackResult result = new LoopbackResult();
            result.ClientException = RunClient(clientProtocol, client, guard, network, options.ClientBody);
            result.ServerException = serverTask.Shutdown(serverThread);
            return result;
        }

        /// <summary>Send one datagram of the given length and check that the server echoes it back.</summary>
        internal static void Echo(DtlsTransport dtlsClient, int length)
        {
            byte[] data = new byte[length];
            Arrays.Fill(data, (byte)length);
            dtlsClient.Send(data, 0, data.Length);

            byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
            for (int attempt = 0; attempt < EchoAttempts; ++attempt)
            {
                int received = dtlsClient.Receive(buf, 0, buf.Length, EchoWaitMillis);
                if (received >= 0)
                {
                    Assert.IsTrue(Arrays.AreEqual(data, 0, data.Length, buf, 0, received), "echo mismatch");
                    return;
                }
            }
            Assert.Fail("no echo received from server");
        }

        private static void CloseQuietly(DatagramTransport transport)
        {
            if (transport == null)
                return;

            try
            {
                transport.Close();
            }
            catch (Exception)
            {
            }
        }

        private static Exception RunClient(DtlsClientProtocol clientProtocol, TlsClient client,
            ClientTransportGuard clientTransport, MockDatagramAssociation network,
            Action<DtlsTransport, MockDatagramAssociation> clientBody)
        {
            DtlsTransport dtlsClient = null;
            try
            {
                dtlsClient = clientProtocol.Connect(client, clientTransport);
                clientTransport.NotifyHandshakeComplete();

                if (clientBody != null)
                {
                    clientBody(dtlsClient, network);
                }
                else
                {
                    for (int i = 1; i <= 10; ++i)
                    {
                        Echo(dtlsClient, i);
                    }
                }

                // A failure to close cleanly is a failure of the run
                DtlsTransport closing = dtlsClient;
                dtlsClient = null;
                closing.Close();

                return null;
            }
            catch (Exception e)
            {
                TlsTestUtilities.LogException("DTLS client", e);
                return e;
            }
            finally
            {
                // Still open only if the handshake or the body failed
                CloseQuietly(dtlsClient);
                CloseQuietly(clientTransport);
            }
        }

        /// <summary>
        /// The runner's own, outermost wrapper of the client transport, applying the handshake-phase policy. While the
        /// handshake is in progress, a receive that comes up empty after the server thread has failed, or after the
        /// handshake deadline, throws rather than letting a client with no handshake timeout wait forever. Once the
        /// handshake completes, any handshake packet loss is switched off, since application data is never
        /// retransmitted.
        /// </summary>
        private sealed class ClientTransportGuard
            : DatagramTransport
        {
            private readonly DatagramTransport m_transport;
            private readonly UnreliableDatagramTransport m_lossyTransport;
            private readonly ServerTask m_serverTask;
            private readonly long m_handshakeDeadline;

            private volatile bool m_inHandshake = true;

            internal ClientTransportGuard(DatagramTransport transport, UnreliableDatagramTransport lossyTransport,
                ServerTask serverTask)
            {
                m_transport = transport;
                m_lossyTransport = lossyTransport;
                m_serverTask = serverTask;
                m_handshakeDeadline = DateTimeUtilities.CurrentUnixMs() + HandshakeDeadlineMillis;
            }

            internal void NotifyHandshakeComplete()
            {
                m_inHandshake = false;
                m_lossyTransport?.SetPacketLoss(0, 0);
            }

            public int GetReceiveLimit() => m_transport.GetReceiveLimit();

            public int GetSendLimit() => m_transport.GetSendLimit();

            public int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                int length = m_transport.Receive(buf, off, len, waitMillis);
                if (length < 0)
                {
                    CheckHandshakeStalled();
                }
                return length;
            }

#if NET6_0_OR_GREATER
            public int Receive(Span<byte> buffer, int waitMillis)
            {
                int length = m_transport.Receive(buffer, waitMillis);
                if (length < 0)
                {
                    CheckHandshakeStalled();
                }
                return length;
            }
#endif

            public void Send(byte[] buf, int off, int len) => m_transport.Send(buf, off, len);

#if NET6_0_OR_GREATER
            public void Send(ReadOnlySpan<byte> buffer) => m_transport.Send(buffer);
#endif

            public void Close() => m_transport.Close();

            /// <summary>Nothing arrived within the wait: give up on the handshake if there is no longer any prospect
            /// of it completing.</summary>
            private void CheckHandshakeStalled()
            {
                if (!m_inHandshake)
                    return;

                if (m_serverTask.Failed)
                    throw new IOException("DTLS server failed during the handshake");

                if (DateTimeUtilities.CurrentUnixMs() >= m_handshakeDeadline)
                    throw new IOException("DTLS handshake did not complete within " + HandshakeDeadlineMillis + "ms");
            }
        }

        private sealed class ServerTask
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly DatagramTransport m_serverTransport;
            private readonly bool m_useCookieExchange;

            private volatile bool m_isShutdown = false;
            private volatile Exception m_exception = null;

            internal ServerTask(DtlsServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport,
                bool useCookieExchange)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
                m_serverTransport = serverTransport;
                m_useCookieExchange = useCookieExchange;
            }

            /// <summary>Whether the server thread has ended with an exception.</summary>
            internal bool Failed => m_exception != null;

            internal void Run()
            {
                DtlsTransport dtlsServer = null;
                try
                {
                    if (m_useCookieExchange)
                    {
                        DtlsRequest request = AwaitVerifiedRequest();
                        if (request == null)
                            return;

                        dtlsServer = m_serverProtocol.Accept(m_server, m_serverTransport, request);
                    }
                    else
                    {
                        dtlsServer = m_serverProtocol.Accept(m_server, m_serverTransport);
                    }

                    byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsServer.Receive(buf, 0, buf.Length, ServerPollMillis);
                        if (length >= 0)
                        {
                            dtlsServer.Send(buf, 0, length);
                        }
                    }

                    // A failure to close cleanly is a failure of the run
                    DtlsTransport closing = dtlsServer;
                    dtlsServer = null;
                    closing.Close();
                }
                catch (Exception e)
                {
                    TlsTestUtilities.LogException("DTLS server", e);
                    m_exception = e;
                }
                finally
                {
                    CloseQuietly(dtlsServer);
                }
            }

            /// <summary>Stop the echo loop and wait for the server thread; returns what the server threw, if
            /// anything.</summary>
            internal Exception Shutdown(Thread serverThread)
            {
                m_isShutdown = true;

                if (!serverThread.Join(GraceMillis))
                {
                    // Stuck, most likely in Accept because the client never completed the handshake
                    m_server.Cancel();

                    if (!serverThread.Join(JoinTimeoutMillis))
                        throw new TimeoutException("DTLS server thread did not exit");
                }

                return m_exception;
            }

            /// <summary>Run the HelloVerifyRequest cookie exchange, returning the verified request, or null if the
            /// run was shut down before one arrived.</summary>
            private DtlsRequest AwaitVerifiedRequest()
            {
                TlsCrypto serverCrypto = m_server.Crypto;
                DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

                // NOTE: Test value only - would typically be the client IP address
                byte[] clientID = Strings.ToUtf8ByteArray("DtlsLoopbackClient");

                // Receive at a random offset into the buffer, to exercise the offset handling
                int receiveLimit = m_serverTransport.GetReceiveLimit();
                int dummyOffset = serverCrypto.SecureRandom.Next(16) + 1;
                byte[] buf = new byte[dummyOffset + receiveLimit];

                while (!m_isShutdown)
                {
                    int length = m_serverTransport.Receive(buf, dummyOffset, receiveLimit, ServerPollMillis);
                    if (length > 0)
                    {
                        DtlsRequest request = verifier.VerifyRequest(clientID, buf, dummyOffset, length,
                            m_serverTransport);
                        if (request != null)
                            return request;
                    }
                }

                return null;
            }
        }
    }
}
