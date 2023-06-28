using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>
    /// Implements cookie generation/verification for a DTLS server as described in RFC 4347,
    /// 4.2.1. Denial of Service Countermeasures.
    /// </summary>
    /// <remarks>
    /// RFC 4347 4.2.1 additionally recommends changing the secret frequently. This class does not handle that
    /// internally, so the instance should be replaced instead.
    /// </remarks>
    public class DtlsVerifier
    {
        private readonly TlsCrypto m_crypto;
        private readonly byte[] m_macKey;

        public DtlsVerifier(TlsCrypto crypto)
        {
            m_crypto = crypto;
            m_macKey = SecureRandom.GetNextBytes(crypto.SecureRandom, 32);
        }

        public virtual DtlsRequest VerifyRequest(byte[] clientID, byte[] data, int dataOff, int dataLen,
            DatagramSender sender)
        {
            try
            {
                int msgLen = DtlsRecordLayer.ReceiveClientHelloRecord(data, dataOff, dataLen);
                if (msgLen < 0)
                    return null;

                int bodyLength = msgLen - DtlsReliableHandshake.MessageHeaderLength;
                if (bodyLength < 39) // Minimum (syntactically) valid DTLS ClientHello length
                    return null;

                int msgOff = dataOff + DtlsRecordLayer.RecordHeaderLength;

                var buf = DtlsReliableHandshake.ReceiveClientHelloMessage(msg: data, msgOff, msgLen);
                if (buf == null)
                    return null;

                var macInput = new MemoryStream(bodyLength);
                ClientHello clientHello = ClientHello.Parse(buf, dtlsOutput: macInput);
                if (clientHello == null)
                    return null;

                long recordSeq = TlsUtilities.ReadUint48(data, dataOff + 5);

                byte[] cookie = clientHello.Cookie;

                TlsMac mac = m_crypto.CreateHmac(MacAlgorithm.hmac_sha256);
                mac.SetKey(m_macKey, 0, m_macKey.Length);
                mac.Update(clientID, 0, clientID.Length);
                macInput.WriteTo(new TlsMacSink(mac));
                byte[] expectedCookie = mac.CalculateMac();

                if (Arrays.FixedTimeEquals(expectedCookie, cookie))
                {
                    byte[] message = TlsUtilities.CopyOfRangeExact(data, msgOff, msgOff + msgLen);

                    return new DtlsRequest(recordSeq, message, clientHello);
                }

                DtlsReliableHandshake.SendHelloVerifyRequest(sender, recordSeq, expectedCookie);
            }
            catch (IOException)
            {
                // Ignore
            }

            return null;
        }
    }
}
