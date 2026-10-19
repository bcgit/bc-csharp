using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public sealed class PgpTrust
        : PgpObject
    {
        private readonly TrustPacket m_packet;

        /// <summary>Create a new <see cref="PgpTrust"/>.</summary>
        /// <param name="packet">The packet.</param>
        public PgpTrust(TrustPacket packet)
        {
            m_packet = packet ?? throw new ArgumentNullException(nameof(packet));
        }

        /// <summary>Create a new <see cref="PgpTrust"/>.</summary>
        /// <param name="inputStream">The input stream.</param>
        public PgpTrust(BcpgInputStream inputStream)
            : this((TrustPacket)inputStream.ReadPacket())
        {
        }

        /// <summary>Return the level and trust.</summary>
        public byte[] GetLevelAndTrust() => m_packet.GetLevelAndTrustAmount();

        /// <summary>Gets the packet.</summary>
        public TrustPacket Packet => m_packet;
    }
}
