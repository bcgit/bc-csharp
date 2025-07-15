namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket
        : InputStreamPacket
    {
        private readonly int m_version;

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
            m_version = bcpgIn.RequireByte();
        }

        internal int Version => m_version;
    }
}
