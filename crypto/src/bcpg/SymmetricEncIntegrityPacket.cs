namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket
		: InputStreamPacket
	{
		internal readonly int m_version;

		internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
			: base(bcpgIn)
        {
			m_version = bcpgIn.RequireByte();
        }
    }
}
