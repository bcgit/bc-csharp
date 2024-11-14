using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic literal data packet.</remarks>
    public class LiteralDataPacket
        : InputStreamPacket
	{
        private readonly int m_format;
        private readonly byte[] m_fileName;
        private readonly long m_modDate;

		internal LiteralDataPacket(BcpgInputStream bcpgIn)
			: base(bcpgIn)
        {
            m_format = bcpgIn.RequireByte();

            int fileNameLength = bcpgIn.RequireByte();
            m_fileName = new byte[fileNameLength];
			bcpgIn.ReadFully(m_fileName);

            m_modDate = (long)StreamUtilities.RequireUInt32BE(bcpgIn) * 1000L;
        }

		/// <summary>The format tag value.</summary>
		public int Format => m_format;

		/// <summary>The modification time of the file in milli-seconds (since Jan 1, 1970 UTC)</summary>
		public long ModificationTime => m_modDate;

		public string FileName => Strings.FromUtf8ByteArray(m_fileName);

		public byte[] GetRawFileName() => Arrays.Clone(m_fileName);
	}
}
