using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for an experimental packet.</remarks>
    public class ExperimentalPacket
        : ContainedPacket
    {
        private readonly PacketTag m_tag;
        private readonly byte[] m_contents;

		internal ExperimentalPacket(PacketTag tag, BcpgInputStream bcpgIn)
        {
            m_tag = tag;
			m_contents = bcpgIn.ReadAll();
        }

		public PacketTag Tag => m_tag;

		public byte[] GetContents() => (byte[])m_contents.Clone();

		public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(m_tag, m_contents);
        }
    }
}
