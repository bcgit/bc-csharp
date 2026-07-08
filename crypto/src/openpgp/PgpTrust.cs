using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public sealed class PgpTrust
        : PgpObject
    {
        private readonly TrustPacket m_packet;

        public PgpTrust(TrustPacket packet)
        {
            m_packet = packet ?? throw new ArgumentNullException(nameof(packet));
        }

        public PgpTrust(BcpgInputStream inputStream)
            : this((TrustPacket)inputStream.ReadPacket())
        {
        }

        public byte[] GetLevelAndTrust() => m_packet.GetLevelAndTrustAmount();

        public TrustPacket Packet => m_packet;
    }
}
