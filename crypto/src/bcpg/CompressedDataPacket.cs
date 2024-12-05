namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic compressed data object.</remarks>
    public class CompressedDataPacket
        : InputStreamPacket
    {
        private readonly CompressionAlgorithmTag m_algorithm;

		internal CompressedDataPacket(
            BcpgInputStream bcpgIn)
			: base(bcpgIn, PacketTag.CompressedData)
        {
            m_algorithm = (CompressionAlgorithmTag)bcpgIn.RequireByte();
        }

        /// <summary>The algorithm tag value.</summary>
        public CompressionAlgorithmTag Algorithm => m_algorithm;
    }
}
