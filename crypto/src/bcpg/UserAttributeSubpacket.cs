using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user attribute sub-packet.
    */
    public class UserAttributeSubpacket
    {
        internal readonly UserAttributeSubpacketTag	type;
        private readonly bool longLength;   // we preserve this as not everyone encodes length properly.
        protected readonly byte[] data;

        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, byte[] data)
            : this(type, false, data)
        {
        }

        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, bool forceLongLength, byte[] data)
        {
            this.type = type;
            this.longLength = forceLongLength;
            this.data = data;
        }

        public virtual UserAttributeSubpacketTag SubpacketType
        {
            get { return type; }
        }

        /**
        * return the generic data making up the packet.
        */
        public virtual byte[] GetData()
        {
            return data;
        }

        public virtual void Encode(Stream os)
        {
            int bodyLen = data.Length + 1;

            if (longLength || bodyLen > 8383)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[5];
                buf[0] = 0xFF;
                Pack.UInt32_To_BE((uint)bodyLen, buf, 1);
                os.Write(buf);
#else
                os.WriteByte(0xff);
                os.WriteByte((byte)(bodyLen >> 24));
                os.WriteByte((byte)(bodyLen >> 16));
                os.WriteByte((byte)(bodyLen >> 8));
                os.WriteByte((byte)bodyLen);
#endif
            }
            else if (bodyLen < 192)
            {
                os.WriteByte((byte)bodyLen);
            }
            else
            {
                bodyLen -= 192;

                os.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                os.WriteByte((byte)bodyLen);
            }

            os.WriteByte((byte) type);
            os.Write(data, 0, data.Length);
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            UserAttributeSubpacket other = obj as UserAttributeSubpacket;

            if (other == null)
                return false;

            return type == other.type
                && Arrays.AreEqual(data, other.data);
        }

        public override int GetHashCode()
        {
            return type.GetHashCode() ^ Arrays.GetHashCode(data);
        }
    }
}
