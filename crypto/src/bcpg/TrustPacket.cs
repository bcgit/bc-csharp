namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket
        : ContainedPacket
    {
        private readonly byte[] m_levelAndTrustAmount;

		public TrustPacket(BcpgInputStream bcpgIn)
            :base(PacketTag.Trust)
        {
            m_levelAndTrustAmount = bcpgIn.ReadAll();
        }

		public TrustPacket(int trustCode)
            : base(PacketTag.Trust)
        {
			m_levelAndTrustAmount = new byte[]{ (byte)trustCode };
        }

		public byte[] GetLevelAndTrustAmount() => (byte[])m_levelAndTrustAmount.Clone();

		public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(PacketTag.Trust, m_levelAndTrustAmount);
    }
}
