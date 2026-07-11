using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a user ID packet.</summary>
    public class UserIdPacket
        : ContainedPacket, IUserDataPacket
    {
        private readonly byte[] m_idData;

        public UserIdPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        public UserIdPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.UserId, newPacketFormat)
        {
            m_idData = bcpgIn.ReadAll();
        }

        public UserIdPacket(string id)
            : base(PacketTag.UserId)
        {
            m_idData = Strings.ToUtf8ByteArray(id);
        }

        public UserIdPacket(byte[] rawId)
            : base(PacketTag.UserId)
        {
            m_idData = Arrays.Clone(rawId);
        }

        public string GetId() => Strings.FromByteArray(m_idData, 0, m_idData.Length);

        public byte[] GetRawId() => Arrays.Clone(m_idData);

        public override bool Equals(object obj)
        {
            return obj is UserIdPacket that
                && Arrays.AreEqual(this.m_idData, that.m_idData);
        }

        public override int GetHashCode() => Arrays.GetHashCode(m_idData);

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.UserId, m_idData);
    }
}
