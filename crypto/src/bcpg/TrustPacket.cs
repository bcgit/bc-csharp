using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket
        : ContainedPacket
    {
        private readonly byte[] m_levelAndTrustAmount;

        /// <summary>Create a new <see cref="TrustPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public TrustPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="TrustPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public TrustPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Trust, newPacketFormat)
        {
            m_levelAndTrustAmount = bcpgIn.ReadAll();
        }

        /// <summary>Create a new <see cref="TrustPacket"/>.</summary>
        /// <param name="trustCode">The trust code.</param>
        public TrustPacket(int trustCode)
            : base(PacketTag.Trust)
        {
            m_levelAndTrustAmount = new byte[]{ (byte)trustCode };
        }

        /// <summary>Return the level and trust amount.</summary>
        public byte[] GetLevelAndTrustAmount() => Arrays.Clone(m_levelAndTrustAmount);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Trust, m_levelAndTrustAmount);
    }
}
