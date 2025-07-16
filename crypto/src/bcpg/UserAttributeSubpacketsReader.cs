using System.IO;

using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Parser for user attribute subpackets</summary>
    public class UserAttributeSubpacketsParser
    {
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

            // TODO Configurable upper limit
            if (bodyLen < 1U || bodyLen > int.MaxValue)
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
