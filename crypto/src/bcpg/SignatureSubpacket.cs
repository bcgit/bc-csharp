using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a PGP Signature sub-packet.</remarks>
    public class SignatureSubpacket
    {
        private readonly SignatureSubpacketTag type;
        private readonly bool critical;
        private readonly bool isLongLength;
		internal byte[] data;

		protected internal SignatureSubpacket(
            SignatureSubpacketTag	type,
            bool					critical,
            bool                    isLongLength,
            byte[]					data)
        {
            this.type = type;
            this.critical = critical;
            this.isLongLength = isLongLength;
            this.data = data;
        }

        public SignatureSubpacketTag SubpacketType
        {
			get { return type; }
        }

        public bool IsCritical()
        {
            return critical;
        }

        public bool IsLongLength()
        {
            return isLongLength;
        }

        /// <summary>Return the generic data making up the packet.</summary>
        public byte[] GetData()
        {
            return (byte[])data.Clone();
        }

		public void Encode(
            Stream os)
        {
            int bodyLen = data.Length + 1;

            if (isLongLength || bodyLen > 8383)
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

            if (critical)
            {
                os.WriteByte((byte)(0x80 | (int) type));
            }
            else
            {
                os.WriteByte((byte) type);
            }

            os.Write(data, 0, data.Length);
        }

        public override int GetHashCode()
        {
            return (critical ? 1 : 0) + 7 * (int)type + 49 * Arrays.GetHashCode(data);
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            if (!(obj is SignatureSubpacket other))
                return false;

            return this.type == other.type
                && this.critical == other.critical
                && Arrays.AreEqual(this.data, other.data);
        }
    }
}
