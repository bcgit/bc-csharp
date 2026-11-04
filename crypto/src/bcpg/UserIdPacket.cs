using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a user ID packet.</summary>
    public class UserIdPacket
        : ContainedPacket, IUserDataPacket
    {
        private readonly byte[] m_idData;

        /// <summary>Create a new <see cref="UserIdPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public UserIdPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="UserIdPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public UserIdPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.UserId, newPacketFormat)
        {
            m_idData = bcpgIn.ReadAll();
        }

        /// <summary>Create a new <see cref="UserIdPacket"/>.</summary>
        /// <param name="id">The id.</param>
        public UserIdPacket(string id)
            : base(PacketTag.UserId)
        {
            m_idData = Strings.ToUtf8ByteArray(id);
        }

        /// <summary>Create a new <see cref="UserIdPacket"/>.</summary>
        /// <param name="rawId">The raw id.</param>
        public UserIdPacket(byte[] rawId)
            : base(PacketTag.UserId)
        {
            m_idData = Arrays.Clone(rawId);
        }

        /// <summary>Return the id.</summary>
        public string GetId() => Strings.FromByteArray(m_idData, 0, m_idData.Length);

        /// <summary>Return the raw id.</summary>
        public byte[] GetRawId() => Arrays.Clone(m_idData);

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj is UserIdPacket that
                && Arrays.AreEqual(this.m_idData, that.m_idData);
        }

        /// <inheritdoc/>
        public override int GetHashCode() => Arrays.GetHashCode(m_idData);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.UserId, m_idData);
    }
}
