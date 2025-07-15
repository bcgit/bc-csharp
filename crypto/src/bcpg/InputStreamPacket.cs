namespace Org.BouncyCastle.Bcpg
{
    public class InputStreamPacket
        : Packet
    {
        private readonly BcpgInputStream m_bcpgIn;

        public InputStreamPacket(BcpgInputStream bcpgIn)
        {
            m_bcpgIn = bcpgIn;
        }

        /// <summary>Note: you can only read from this once...</summary>
        public BcpgInputStream GetInputStream() => m_bcpgIn;
    }
}
