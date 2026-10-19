using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>A packet with an unknown tag, kept as raw bytes.</summary>
    public sealed class UnknownPacket
        : ContainedPacket
    {
        private readonly byte[] m_contents;

        /// <summary>Create a new <see cref="UnknownPacket"/>.</summary>
        /// <param name="tag">The tag.</param>
        /// <param name="bcpgIn">The bcpg in.</param>
        public UnknownPacket(PacketTag tag, BcpgInputStream bcpgIn)
            : this(tag, bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="UnknownPacket"/>.</summary>
        /// <param name="tag">The tag.</param>
        /// <param name="bcpgIn">The bcpg in.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public UnknownPacket(PacketTag tag, BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(tag, newPacketFormat)
        {
            m_contents = bcpgIn.ReadAll();
        }

        /// <summary>Return the contents.</summary>
        public byte[] GetContents() => Arrays.Clone(m_contents);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, m_contents);
    }
}
