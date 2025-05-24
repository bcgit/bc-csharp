using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for an experimental packet.</remarks>
    public class ExperimentalPacket
        : ContainedPacket
    {
        private readonly byte[] m_contents;

		internal ExperimentalPacket(PacketTag tag, BcpgInputStream bcpgIn)
            :base(tag)
        {
			m_contents = bcpgIn.ReadAll();
        }

		public byte[] GetContents() => (byte[])m_contents.Clone();

		public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(Tag, m_contents);
        }
    }
}
