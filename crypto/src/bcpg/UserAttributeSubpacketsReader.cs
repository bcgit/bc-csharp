using System;
using System.IO;

using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Parser for user attribute subpackets</summary>
    public class UserAttributeSubpacketsParser
    {
        // Absolute upper bound on a single user attribute subpacket body. A crafted long-length
        // header could otherwise force a multi-gigabyte new byte[] (below) before any body bytes
        // are read, a pre-auth allocation DoS. 2 MiB matches SignaturePacket.MaxSubpacketLength;
        // subpackets are not expected to approach it.
        public static readonly int MaxSubpacketLength = 2 * 1024 * 1024;

        private readonly Stream m_input;
        private readonly int m_limit;

        public UserAttributeSubpacketsParser(Stream input)
            : this(input, StreamUtilities.FindLimit(input))
        {
        }

        public UserAttributeSubpacketsParser(Stream input, int limit)
        {
            m_input = input;
            m_limit = limit;
        }

        public virtual UserAttributeSubpacket ReadPacket()
        {
            uint bodyLen = StreamUtilities.ReadBodyLen(m_input, out var streamFlags);
            if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Eof))
                return null;

            if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial))
                throw new MalformedPacketException("unrecognised length reading user attribute sub packet");

            if (bodyLen < 1U)
                throw new MalformedPacketException("Body length octet too small.");
            if (bodyLen > m_limit)
                throw new MalformedPacketException($"Body length octet ({bodyLen}) exceeds limit ({m_limit}).");
            // Absolute cap, independent of the FindLimit() hint, so a crafted length cannot drive a huge allocation.
            if (bodyLen > MaxSubpacketLength)
                throw new MalformedPacketException(
                    $"Body length octet ({bodyLen}) exceeds max user attribute subpacket length ({MaxSubpacketLength}).");

            bool isLongLength = streamFlags.HasFlag(StreamUtilities.StreamFlags.LongLength);

            int tag = StreamUtilities.RequireByte(m_input);
            byte[] data = new byte[bodyLen - 1];

            StreamUtilities.RequireBytes(m_input, data);

            UserAttributeSubpacketTag type = (UserAttributeSubpacketTag)tag;
            try
            {
                switch (type)
                {
                case UserAttributeSubpacketTag.ImageAttribute:
                    return new ImageAttrib(isLongLength, data);
                }
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed UserAttribute subpacket.", e);
            }

            return new UserAttributeSubpacket(type, isLongLength, data);
        }
    }
}
