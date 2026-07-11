using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a modification detection code packet.</summary>
    public class ModDetectionCodePacket
        : ContainedPacket
    {
        private readonly byte[] m_digest;

        internal ModDetectionCodePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal ModDetectionCodePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.ModificationDetectionCode, newPacketFormat)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            m_digest = new byte[20];
            bcpgIn.ReadFully(m_digest);
        }

        public ModDetectionCodePacket(byte[] digest)
            : base(PacketTag.ModificationDetectionCode)
        {
            if (digest == null)
                throw new ArgumentNullException(nameof(digest));

            m_digest = Arrays.Clone(digest);
        }

        internal byte[] Digest => m_digest;

        public byte[] GetDigest() => Arrays.Clone(m_digest);

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.ModificationDetectionCode, m_digest);
    }
}
