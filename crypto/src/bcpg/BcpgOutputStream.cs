using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic output stream.</remarks>
    public class BcpgOutputStream
        : BaseOutputStream
    {
		internal static BcpgOutputStream Wrap(Stream outStr)
		{
			if (outStr is BcpgOutputStream bcpgOutputStream)
				return bcpgOutputStream;

			return new BcpgOutputStream(outStr);
		}

		private Stream outStr;
        private bool useOldFormat;
        private byte[] partialBuffer;
        private int partialBufferLength;
        private int partialPower;
        private int partialOffset;
        private const int BufferSizePower = 16; // 2^16 size buffer on long files

		/// <summary>Create a stream representing a general packet.</summary>
		/// <param name="outStr">Output stream to write to.</param>
		public BcpgOutputStream(Stream outStr)
            : this(outStr, false)
        {
        }

        /// <summary>Base constructor specifying whether or not to use packets in the new format wherever possible.
        /// </summary>
		/// <param name="outStr">Output stream to write to.</param>
        /// <param name="newFormatOnly"><c>true</c> if use new format packets, <c>false</c> if backwards compatible
        /// preferred.</param>
        public BcpgOutputStream(Stream outStr, bool newFormatOnly)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            this.useOldFormat = !newFormatOnly;
        }

        /// <summary>Create a stream representing an old style partial object.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">The packet tag for the object.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            this.WriteHeader(tag, true, true, 0);
        }

		/// <summary>Create a stream representing a general packet.</summary>
		/// <param name="outStr">Output stream to write to.</param>
		/// <param name="tag">Packet tag.</param>
		/// <param name="length">Size of chunks making up the packet.</param>
		/// <param name="oldFormat">If true, the header is written out in old format.</param>
		public BcpgOutputStream(Stream outStr, PacketTag tag, long length, bool oldFormat)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));

            if (length > 0xFFFFFFFFL)
            {
                this.WriteHeader(tag, false, true, 0);
                this.partialBufferLength = 1 << BufferSizePower;
                this.partialBuffer = new byte[partialBufferLength];
				this.partialPower = BufferSizePower;
				this.partialOffset = 0;
            }
            else
            {
                this.WriteHeader(tag, oldFormat, false, length);
            }
        }

		/// <summary>Create a new style partial input stream buffered into chunks.</summary>
		/// <param name="outStr">Output stream to write to.</param>
		/// <param name="tag">Packet tag.</param>
		/// <param name="length">Size of chunks making up the packet.</param>
		public BcpgOutputStream(Stream outStr, PacketTag tag, long length)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            this.WriteHeader(tag, false, false, length);
        }

		/// <summary>Create a new style partial input stream buffered into chunks.</summary>
		/// <param name="outStr">Output stream to write to.</param>
		/// <param name="tag">Packet tag.</param>
		/// <param name="buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, byte[] buffer)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            this.WriteHeader(tag, false, true, 0);

			this.partialBuffer = buffer;

			uint length = (uint) partialBuffer.Length;
            for (partialPower = 0; length != 1; partialPower++)
            {
                length >>= 1;
            }

			if (partialPower > 30)
                throw new IOException("Buffer cannot be greater than 2^30 in length.");

            this.partialBufferLength = 1 << partialPower;
            this.partialOffset = 0;
        }

		private void WriteNewPacketLength(long bodyLen)
        {
            if (bodyLen < 192)
            {
                outStr.WriteByte((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                outStr.WriteByte((byte)(((bodyLen >> 8) & 0xff) + 192));
                outStr.WriteByte((byte)bodyLen);
            }
            else
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[5];
                buf[0] = 0xFF;
                Pack.UInt32_To_BE((uint)bodyLen, buf, 1);
                outStr.Write(buf);
#else
                outStr.WriteByte(0xff);
                outStr.WriteByte((byte)(bodyLen >> 24));
                outStr.WriteByte((byte)(bodyLen >> 16));
                outStr.WriteByte((byte)(bodyLen >> 8));
                outStr.WriteByte((byte)bodyLen);
#endif
            }
        }

        private void WriteHeader(PacketTag packetTag, bool oldPackets, bool partial, long bodyLen)
        {
            int hdr = 0x80;

            if (partialBuffer != null)
            {
                PartialFlushLast();
                partialBuffer = null;
            }

            int tag = (int)packetTag;

            // only tags <= 0xF in value can be written as old packets.
            if (tag <= 0xF && oldPackets)
            {
                hdr |= tag << 2;

                if (partial)
                {
                    this.WriteByte((byte)(hdr | 0x03));
                }
                else
                {
                    if (bodyLen <= 0xff)
                    {
                        this.WriteByte((byte) hdr);
                        this.WriteByte((byte)bodyLen);
                    }
                    else if (bodyLen <= 0xffff)
                    {
                        this.WriteByte((byte)(hdr | 0x01));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)(bodyLen));
                    }
                    else
                    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        Span<byte> buf = stackalloc byte[5];
                        buf[0] = (byte)(hdr | 0x02);
                        Pack.UInt32_To_BE((uint)bodyLen, buf, 1);
                        this.Write(buf);
#else
                        this.WriteByte((byte)(hdr | 0x02));
                        this.WriteByte((byte)(bodyLen >> 24));
                        this.WriteByte((byte)(bodyLen >> 16));
                        this.WriteByte((byte)(bodyLen >> 8));
                        this.WriteByte((byte)bodyLen);
#endif
                    }
                }
            }
            else
            {
                hdr |= 0x40 | tag;
                this.WriteByte((byte) hdr);

                if (partial)
                {
                    partialOffset = 0;
                }
                else
                {
                    this.WriteNewPacketLength(bodyLen);
                }
            }
        }

        private void PartialFlush()
        {
            outStr.WriteByte((byte)(0xE0 | partialPower));
            outStr.Write(partialBuffer, 0, partialBufferLength);
            partialOffset = 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void PartialFlush(ref ReadOnlySpan<byte> buffer)
        {
            outStr.WriteByte((byte)(0xE0 | partialPower));
            outStr.Write(buffer[..partialBufferLength]);
            buffer = buffer[partialBufferLength..];
        }
#endif

        private void PartialFlushLast()
        {
            WriteNewPacketLength(partialOffset);
            outStr.Write(partialBuffer, 0, partialOffset);
            partialOffset = 0;
        }

        private void PartialWrite(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            PartialWrite(buffer.AsSpan(offset, count));
#else
            if (partialOffset == partialBufferLength)
            {
                PartialFlush();
            }

            if (count <= (partialBufferLength - partialOffset))
            {
                Array.Copy(buffer, offset, partialBuffer, partialOffset, count);
                partialOffset += count;
                return;
            }

            int diff = partialBufferLength - partialOffset;
            Array.Copy(buffer, offset, partialBuffer, partialOffset, diff);
            offset += diff;
            count -= diff;
            PartialFlush();
            while (count > partialBufferLength)
            {
                Array.Copy(buffer, offset, partialBuffer, 0, partialBufferLength);
                offset += partialBufferLength;
                count -= partialBufferLength;
                PartialFlush();
            }
            Array.Copy(buffer, offset, partialBuffer, 0, count);
            partialOffset = count;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void PartialWrite(ReadOnlySpan<byte> buffer)
        {
            if (partialOffset == partialBufferLength)
            {
                PartialFlush();
            }

            if (buffer.Length <= (partialBufferLength - partialOffset))
            {
                buffer.CopyTo(partialBuffer.AsSpan(partialOffset));
                partialOffset += buffer.Length;
                return;
            }

            int diff = partialBufferLength - partialOffset;
            buffer[..diff].CopyTo(partialBuffer.AsSpan(partialOffset));
            buffer = buffer[diff..];
            PartialFlush();
            while (buffer.Length > partialBufferLength)
            {
                PartialFlush(ref buffer);
            }
            buffer.CopyTo(partialBuffer);
            partialOffset = buffer.Length;
        }
#endif

        private void PartialWriteByte(byte value)
        {
            if (partialOffset == partialBufferLength)
            {
                PartialFlush();
            }

            partialBuffer[partialOffset++] = value;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (partialBuffer != null)
            {
                PartialWrite(buffer, offset, count);
            }
            else
            {
                outStr.Write(buffer, offset, count);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (partialBuffer != null)
            {
                PartialWrite(buffer);
            }
            else
            {
                outStr.Write(buffer);
            }
        }
#endif

        public override void WriteByte(byte value)
        {
            if (partialBuffer != null)
            {
                PartialWriteByte(value);
            }
            else
            {
                outStr.WriteByte(value);
            }
        }

        // Additional helper methods to write primitive types
        internal virtual void WriteShort(
			short n)
		{
			this.Write(
				(byte)(n >> 8),
				(byte)n);
		}
		internal virtual void WriteInt(
			int n)
		{
			this.Write(
				(byte)(n >> 24),
				(byte)(n >> 16),
				(byte)(n >> 8),
				(byte)n);
		}
		internal virtual void WriteLong(
			long n)
		{
			this.Write(
				(byte)(n >> 56),
				(byte)(n >> 48),
				(byte)(n >> 40),
				(byte)(n >> 32),
				(byte)(n >> 24),
				(byte)(n >> 16),
				(byte)(n >> 8),
				(byte)n);
		}

		public void WritePacket(ContainedPacket p)
        {
            p.Encode(this);
        }

        internal void WritePacket(PacketTag tag, byte[] body)
        {
            WritePacket(tag, body, useOldFormat);
        }

        internal void WritePacket(PacketTag tag, byte[] body, bool oldFormat)
        {
            this.WriteHeader(tag, oldFormat, false, body.Length);
            this.Write(body);
        }

		public void WriteObject(BcpgObject bcpgObject)
        {
            bcpgObject.Encode(this);
        }

		public void WriteObjects(params BcpgObject[] v)
		{
			foreach (BcpgObject o in v)
			{
				o.Encode(this);
			}
		}

		/// <summary>Flush the underlying stream.</summary>
        public override void Flush()
        {
            outStr.Flush();
        }

		/// <summary>Finish writing out the current packet without closing the underlying stream.</summary>
        public void Finish()
        {
            if (partialBuffer != null)
            {
                PartialFlushLast();
                Array.Clear(partialBuffer, 0, partialBuffer.Length);
                partialBuffer = null;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
			    this.Finish();
			    outStr.Flush();
                outStr.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
