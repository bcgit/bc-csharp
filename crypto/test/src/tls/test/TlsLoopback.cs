using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>Runs a TLS client and server against each other over an in-memory pipe.</summary>
    /// <remarks>
    /// The server runs on its own thread and echoes application data until the client closes. The client, on the
    /// calling thread, connects, writes a block of random data and checks the echo. Whatever either end throws is
    /// captured into the <see cref="LoopbackResult"/> rather than propagated, so the caller decides which failures
    /// are expected. The runner closes both pipes if the protocols have not already done so, so a failure at one end
    /// cannot leave the other blocked in a read.
    /// </remarks>
    internal static class TlsLoopback
    {
        private const int EchoLength = 1000;
        private const int JoinTimeoutMillis = 30000;

        internal static LoopbackResult Run(TlsClient client, TlsServer server) => Run(client, server, null);

        /// <param name="clientProtocolFactory">Creates the client protocol over the given transport stream, or null
        /// for a plain <see cref="TlsClientProtocol"/>.</param>
        internal static LoopbackResult Run(TlsClient client, TlsServer server,
            Func<Stream, TlsClientProtocol> clientProtocolFactory)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = clientProtocolFactory == null
                ?   new TlsClientProtocol(clientPipe)
                :   clientProtocolFactory(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            LoopbackResult result = new LoopbackResult();

            Thread serverThread = new Thread(() => result.ServerException = RunServer(serverProtocol, server));
            serverThread.Start();

            result.ClientException = RunClient(clientProtocol, client);

            // Snapshot before the safety-net close: the question is whether the protocol closed its own stream
            result.ClientStreamClosed = clientPipe.IsClosed;
            clientPipe.Dispose();

            if (!serverThread.Join(JoinTimeoutMillis))
                throw new TimeoutException("TLS server thread did not exit");

            result.ServerStreamClosed = serverPipe.IsClosed;
            serverPipe.Dispose();

            return result;
        }

        private static Exception RunClient(TlsClientProtocol clientProtocol, TlsClient client)
        {
            try
            {
                clientProtocol.Connect(client);

                byte[] data = new byte[EchoLength];
                client.Crypto.SecureRandom.NextBytes(data);

                using (var stream = clientProtocol.Stream)
                {
                    stream.Write(data, 0, data.Length);

                    byte[] echo = new byte[data.Length];
                    int count = Streams.ReadFully(stream, echo);

                    Assert.AreEqual(data.Length, count, "echo length");
                    Assert.IsTrue(Arrays.AreEqual(data, echo), "echo content");
                }

                return null;
            }
            catch (Exception e)
            {
                TlsTestUtilities.LogException("TLS client", e);
                return e;
            }
        }

        private static Exception RunServer(TlsServerProtocol serverProtocol, TlsServer server)
        {
            try
            {
                serverProtocol.Accept(server);

                using (var stream = serverProtocol.Stream)
                {
                    Streams.PipeAll(stream, stream);
                }

                return null;
            }
            catch (Exception e)
            {
                TlsTestUtilities.LogException("TLS server", e);
                return e;
            }
        }
    }
}
