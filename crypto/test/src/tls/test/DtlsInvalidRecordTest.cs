using NUnit.Framework;

using Org.BouncyCastle.Security;

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

            var options = new DtlsLoopbackOptions
            {
                ClientBody = (dtlsClient, network) =>
                    InjectForgedRecords(dtlsClient, network, client.Crypto.SecureRandom, forgedBodyLengths),
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }

        /// <summary>
        /// Sending on one of the association's raw transports delivers a datagram to the other peer's receive queue,
        /// which is how the forgeries get "on the wire" without going through either DTLS record layer.
        /// </summary>
        private static void InjectForgedRecords(DtlsTransport dtlsClient, MockDatagramAssociation network,
            SecureRandom random, int[] forgedBodyLengths)
        {
            // Confirm the association is up and carrying application data.
            DtlsLoopback.Echo(dtlsClient, 1);

            // A sequence number well ahead of the replay window, so that each forgery is "fresh".
            long forgedSeq = 1L << 40;

            for (int i = 0; i < forgedBodyLengths.Length; ++i)
            {
                int bodyLength = forgedBodyLengths[i];

                // Off-path forgery towards the server.
                byte[] toServer = CreateForgedRecord(random, forgedSeq++, bodyLength);
                network.Client.Send(toServer, 0, toServer.Length);

                // Off-path forgery towards the client.
                byte[] toClient = CreateForgedRecord(random, forgedSeq++, bodyLength);
                network.Server.Send(toClient, 0, toClient.Length);

                // Both peers must have discarded the forgery and still be able to exchange application data.
                DtlsLoopback.Echo(dtlsClient, i + 2);
            }
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
    }
}
