using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsHandshakeTimeoutTest
    {
        private const int HandshakeTimeoutMillis = 500;

        /// <summary>
        /// A peer that keeps sending well formed, ignorable records - a warning alert the client is required to
        /// tolerate - one at a time, forever. Every read completes, so no per-read timeout can end this; only a total
        /// handshake deadline can.
        /// </summary>
        [Test]
        public void SlowPeerTimesOut()
        {
            // NOTE: the record limit only bounds the failure case (with no deadline the handshake would otherwise run
            // forever); it is far more than any passing run reaches.
            Stream input = new AlertDripInputStream(HandshakeTimeoutMillis / 10, 200);

            TlsClientProtocol protocol = new TlsClientProtocol(input, Stream.Null);

            long start = DateTimeUtilities.CurrentUnixMs();
            try
            {
                protocol.Connect(CreateClient(HandshakeTimeoutMillis));
                Assert.Fail("handshake should have timed out");
            }
            catch (TlsTimeoutException)
            {
                long elapsed = DateTimeUtilities.CurrentUnixMs() - start;
                Assert.Less(elapsed, 10L * HandshakeTimeoutMillis, "handshake timed out too late (" + elapsed + "ms)");
            }
        }

        /// <summary>
        /// The same peer, with no handshake timeout configured. A zero timeout means an infinite one, so the handshake
        /// must not be abandoned - this is the compatibility case for every existing peer, all of which inherit zero
        /// from AbstractTlsPeer.
        /// </summary>
        [Test]
        public void NoTimeoutIsInfinite()
        {
            Stream input = new AlertDripInputStream(HandshakeTimeoutMillis / 10, 40);

            TlsClientProtocol protocol = new TlsClientProtocol(input, Stream.Null);

            try
            {
                protocol.Connect(CreateClient(0));
                Assert.Fail("handshake should not have completed");
            }
            catch (TlsTimeoutException)
            {
                Assert.Fail("handshake timed out with no handshake timeout configured");
            }
            catch (IOException)
            {
                // Expected: the peer runs out of records long after any deadline would have fired
            }
        }

        private static MockTlsClient CreateClient(int handshakeTimeoutMillis) =>
            new MockTlsClient(null) { HandshakeTimeoutMillis = handshakeTimeoutMillis };

        private class AlertDripInputStream
            : BaseInputStream
        {
            private static readonly byte[] WarningAlertRecord = new byte[]{
                (byte)ContentType.alert, 0x03, 0x03, 0x00, 0x02,
                (byte)AlertLevel.warning, (byte)AlertDescription.user_canceled };

            private readonly int m_delayMillis;
            private readonly int m_recordLimit;

            private int m_recordCount = 0;
            private int m_pos = 0;

            internal AlertDripInputStream(int delayMillis, int recordLimit)
            {
                m_delayMillis = delayMillis;
                m_recordLimit = recordLimit;
            }

            public override int ReadByte()
            {
                if (m_pos == 0)
                {
                    if (m_recordLimit >= 0 && m_recordCount >= m_recordLimit)
                        return -1;

                    ++m_recordCount;

                    Thread.Sleep(m_delayMillis);
                }

                int result = WarningAlertRecord[m_pos++];
                m_pos %= WarningAlertRecord.Length;
                return result;
            }
        }
    }
}
