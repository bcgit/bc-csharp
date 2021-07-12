using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolNonBlockingTest
    {
        [Test]
        public void TestClientServerFragmented()
        {
            // tests if it's really non-blocking when partial records arrive
            ImplTestClientServer(true);
        }

        [Test]
        public void TestClientServerNonFragmented()
        {
            ImplTestClientServer(false);
        }

        private static void ImplTestClientServer(bool fragment)
        {
            TlsClientProtocol clientProtocol = new TlsClientProtocol();
            TlsServerProtocol serverProtocol = new TlsServerProtocol();

            MockTlsClient client = new MockTlsClient(null);
            MockTlsServer server = new MockTlsServer();

            clientProtocol.Connect(client);
            serverProtocol.Accept(server);

            // pump handshake
            bool hadDataFromServer = true;
            bool hadDataFromClient = true;
            while (hadDataFromServer || hadDataFromClient)
            {
                hadDataFromServer = PumpData(serverProtocol, clientProtocol, fragment);
                hadDataFromClient = PumpData(clientProtocol, serverProtocol, fragment);
            }

            // send data in both directions
            byte[] data = new byte[1024];
            client.Crypto.SecureRandom.NextBytes(data);

            WriteAndRead(clientProtocol, serverProtocol, data, fragment);
            WriteAndRead(serverProtocol, clientProtocol, data, fragment);

            // close the connection
            clientProtocol.Close();
            PumpData(clientProtocol, serverProtocol, fragment);
            serverProtocol.CloseInput();
            CheckClosed(serverProtocol);
            CheckClosed(clientProtocol);
        }

        private static void WriteAndRead(TlsProtocol writer, TlsProtocol reader, byte[] data, bool fragment)
        {
            int dataSize = data.Length;
            writer.WriteApplicationData(data, 0, dataSize);
            PumpData(writer, reader, fragment);

            Assert.AreEqual(dataSize, reader.GetAvailableInputBytes());
            byte[] readData = new byte[dataSize];
            reader.ReadInput(readData, 0, dataSize);
            AssertArrayEquals(data, readData);
        }

        private static bool PumpData(TlsProtocol from, TlsProtocol to, bool fragment)
        {
            int byteCount = from.GetAvailableOutputBytes();
            if (byteCount == 0)
                return false;

            if (fragment)
            {
                byte[] buffer = new byte[1];
                while (from.GetAvailableOutputBytes() > 0)
                {
                    from.ReadOutput(buffer, 0, 1);
                    to.OfferInput(buffer);
                }
            }
            else
            {
                byte[] buffer = new byte[byteCount];
                from.ReadOutput(buffer, 0, buffer.Length);
                to.OfferInput(buffer);
            }

            return true;
        }

        private static void CheckClosed(TlsProtocol protocol)
        {
            Assert.IsTrue(protocol.IsClosed);

            try
            {
                protocol.OfferInput(new byte[10]);
                Assert.Fail("Input was accepted after close");
            }
            catch (IOException e)
            {
            }

            try
            {
                protocol.WriteApplicationData(new byte[10], 0, 10);
                Assert.Fail("Output was accepted after close");
            }
            catch (IOException e)
            {
            }
        }

        private static void AssertArrayEquals(byte[] a, byte[] b)
        {
            Assert.IsTrue(Arrays.AreEqual(a, b));
        }
    }
}
