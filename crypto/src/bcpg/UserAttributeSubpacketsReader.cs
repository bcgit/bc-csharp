using System.IO;

using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Parser for user attribute subpackets</summary>
    public class UserAttributeSubpacketsParser
    {
        // Absolute upper bound on a single user attribute subpacket body. A crafted long-length
        // header could otherwise force a multi-gigabyte new byte[] (below) before any body bytes
        // are read, a pre-auth allocation DoS. 2 MiB matches bc-java's SignaturePacket
        // MAX_SUBPACKET_LEN ceiling; image subpackets are not expected to approach it.
        private const int MaxSubpacketLength = 2 * 1024 * 1024;

        private readonly Stream m_input;

        public UserAttributeSubpacketsParser(Stream input)
        {
            m_input = input;
        }

        public virtual UserAttributeSubpacket ReadPacket()
        {
            uint bodyLen = StreamUtilities.ReadBodyLen(m_input, out var streamFlags);
            if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Eof))
                return null;

            if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial))
                throw new IOException("unrecognised length reading user attribute subpacket");

            bool isLongLength = streamFlags.HasFlag(StreamUtilities.StreamFlags.LongLength);

            if (bodyLen < 1U || bodyLen > MaxSubpacketLength)
                throw new EndOfStreamException("out of range data found in user attribute subpacket");

            int tag = StreamUtilities.RequireByte(m_input);
            byte[] data = new byte[bodyLen - 1];

            StreamUtilities.RequireBytes(m_input, data);

            UserAttributeSubpacketTag type = (UserAttributeSubpacketTag)tag;
            switch (type)
            {
            case UserAttributeSubpacketTag.ImageAttribute:
                return new ImageAttrib(isLongLength, data);
            }
            return new UserAttributeSubpacket(type, isLongLength, data);
        }
    }
}
