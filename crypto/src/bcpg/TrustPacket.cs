using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a trust packet.</summary>
    public class TrustPacket
        : ContainedPacket
    {
        private readonly byte[] m_levelAndTrustAmount;

        public TrustPacket(BcpgInputStream bcpgIn)
        {
            m_levelAndTrustAmount = bcpgIn.ReadAll();
        }

        public TrustPacket(int trustCode)
        {
            m_levelAndTrustAmount = new byte[]{ (byte)trustCode };
        }

        public byte[] GetLevelAndTrustAmount() => Arrays.Clone(m_levelAndTrustAmount);

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(PacketTag.Trust, m_levelAndTrustAmount);
    }
}
