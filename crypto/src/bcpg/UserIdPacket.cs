using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user ID packet.
    */
    public class UserIdPacket
        : ContainedPacket, IUserDataPacket
    {
        private readonly byte[] idData;

        public UserIdPacket(BcpgInputStream bcpgIn)
            :base(PacketTag.UserId)
        {
            this.idData = bcpgIn.ReadAll();
        }

		public UserIdPacket(string id)
            : base(PacketTag.UserId)
        {
            this.idData = Encoding.UTF8.GetBytes(id);
        }

        public UserIdPacket(byte[] rawId)
            : base(PacketTag.UserId)
        {
            this.idData = Arrays.Clone(rawId);
        }

        public string GetId()
        {
			return Encoding.UTF8.GetString(idData, 0, idData.Length);
        }

        public byte[] GetRawId() => Arrays.Clone(idData);

        public override bool Equals(object obj)
        {
            if (!(obj is UserIdPacket other))
                return false;

            return Arrays.AreEqual(this.idData, other.idData);
        }

        public override int GetHashCode()
        {
            return Arrays.GetHashCode(this.idData);
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.UserId, idData);
        }
    }
}
