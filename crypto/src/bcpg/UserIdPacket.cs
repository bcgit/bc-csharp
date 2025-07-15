using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a user ID packet.</summary>
    public class UserIdPacket
        : ContainedPacket, IUserDataPacket
    {
        private readonly byte[] m_idData;

        public UserIdPacket(BcpgInputStream bcpgIn)
        {
            m_idData = bcpgIn.ReadAll();
        }

        public UserIdPacket(string id)
        {
            m_idData = Encoding.UTF8.GetBytes(id);
        }

        public UserIdPacket(byte[] rawId)
        {
            m_idData = Arrays.Clone(rawId);
        }

        public string GetId() => Encoding.UTF8.GetString(m_idData, 0, m_idData.Length);

        public byte[] GetRawId() => Arrays.Clone(m_idData);

        public override bool Equals(object obj)
        {
            return obj is UserIdPacket that
                && Arrays.AreEqual(this.m_idData, that.m_idData);
        }

        public override int GetHashCode() => Arrays.GetHashCode(m_idData);

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WritePacket(PacketTag.UserId, m_idData);
    }
}
