using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for an experimental packet.</remarks>
    public class ExperimentalPacket
        : ContainedPacket
    {
        private readonly byte[] m_contents;

        internal ExperimentalPacket(PacketTag tag, BcpgInputStream bcpgIn)
            : this(tag, bcpgIn, newPacketFormat: false)
        {
        }

        internal ExperimentalPacket(PacketTag tag, BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(tag, newPacketFormat)
        {
            m_contents = bcpgIn.ReadAll();
        }

        [Obsolete("Use 'PacketTag' instead")]
        public PacketTag Tag => PacketTag;

        /// <summary>Return the contents.</summary>
        public byte[] GetContents() => Arrays.Clone(m_contents);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, m_contents);
    }
}
