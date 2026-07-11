using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic output stream.</remarks>
    // TODO Support leaveOpen setting?
    public class BcpgOutputStream
        : BaseOutputStream
    {
        private const int BufferSizePower = 16; // 2^16 size buffer on long files

        internal static BcpgOutputStream Wrap(Stream outStr)
        {
            if (outStr is BcpgOutputStream bcpgOutputStream)
                return bcpgOutputStream;

            return new BcpgOutputStream(outStr);
        }

        private readonly Stream m_outStr;
        private readonly PacketFormat m_packetFormat;
        private readonly int partialBufferLength;
        private readonly int partialPower;

        private byte[] partialBuffer;
        private int partialOffset;

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        public BcpgOutputStream(Stream outStr)
            : this(outStr, PacketFormat.Roundtrip)
        {
        }

        /// <summary>Base constructor specifying whether or not to use packets in the new format wherever possible.
        /// </summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="newFormatOnly"><c>true</c> if use new format packets, <c>false</c> if backwards compatible
        /// preferred.</param>
        public BcpgOutputStream(Stream outStr, bool newFormatOnly)
            : this(outStr, newFormatOnly ? PacketFormat.Current : PacketFormat.Roundtrip)
        {
        }

        public BcpgOutputStream(Stream outStr, PacketFormat packetFormat)
        {
            m_outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_packetFormat = packetFormat;
        }

        /// <summary>Create a stream representing an old style partial object.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">The packet tag for the object.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag)
        {
            m_outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_packetFormat = PacketFormat.Legacy;

            WriteHeader(tag, oldFormat: true, partial: true, bodyLen: 0L);
        }

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        /// <param name="oldFormat">If true, the header is written out in old format.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, long length, bool oldFormat)
        {
            m_outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_packetFormat = oldFormat ? PacketFormat.Legacy : PacketFormat.Current;

            if (length > 0xFFFFFFFFL)
            {
                WriteHeader(tag, oldFormat: false, partial: true, bodyLen: 0L);

                this.partialBufferLength = 1 << BufferSizePower;
                this.partialBuffer = new byte[partialBufferLength];
                this.partialPower = BufferSizePower;
                this.partialOffset = 0;
            }
            else
            {
                WriteHeader(tag, oldFormat, partial: false, length);
            }
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="length">Size of chunks making up the packet.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, long length)
        {
            m_outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_packetFormat = PacketFormat.Current;

            WriteHeader(tag, oldFormat: false, partial: false, length);
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, byte[] buffer)
        {
            m_outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));
            m_packetFormat = PacketFormat.Current;

            WriteHeader(tag, oldFormat: false, partial: true, bodyLen: 0L);

            this.partialBuffer = buffer;

            uint length = (uint)partialBuffer.Length;
            for (partialPower = 0; length != 1; partialPower++)
            {
                length >>= 1;
            }

            if (partialPower > 30)
                throw new IOException("Buffer cannot be greater than 2^30 in length.");

            this.partialBufferLength = 1 << partialPower;
            this.partialOffset = 0;
        }

        private void WriteHeader(PacketTag packetTag, bool oldFormat, bool partial, long bodyLen)
        {
            int hdr = 0x80;

            if (partialBuffer != null)
            {
                PartialFlushLast();
                partialBuffer = null;
            }

            int tag = (int)packetTag;

            // only tags <= 0xF in value can be written as old packets.
            if (tag <= 0xF && oldFormat)
            {
                hdr |= tag << 2;

                if (partial)
                {
                    WriteByte((byte)(hdr | 0x03));
                }
                else
                {
                    if (bodyLen <= 0xFF)
                    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        Span<byte> buf = stackalloc byte[2];
                        buf[0] = (byte)hdr;
                        buf[1] = (byte)bodyLen;
                        Write(buf);
#else
                        WriteByte((byte)hdr);
                        WriteByte((byte)bodyLen);
#endif
                    }
                    else if (bodyLen <= 0xFFFF)
                    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        Span<byte> buf = stackalloc byte[3];
                        buf[0] = (byte)(hdr | 0x01);
                        Pack.UInt16_To_BE((ushort)bodyLen, buf, 1);
                        Write(buf);
#else
                        WriteByte((byte)(hdr | 0x01));
                        StreamUtilities.WriteUInt16BE(this, (ushort)bodyLen);
#endif
                    }
                    else
                    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        Span<byte> buf = stackalloc byte[5];
                        buf[0] = (byte)(hdr | 0x02);
                        Pack.UInt32_To_BE((uint)bodyLen, buf, 1);
                        Write(buf);
#else
                        WriteByte((byte)(hdr | 0x02));
                        StreamUtilities.WriteUInt32BE(this, (uint)bodyLen);
#endif
                    }
                }
            }
            else
            {
                hdr |= 0x40 | tag;
                WriteByte((byte)hdr);

                if (partial)
                {
                    partialOffset = 0;
                }
                else
                {
                    StreamUtilities.WriteNewPacketLength(m_outStr, bodyLen);
                }
            }
        }

        private void PartialFlush()
        {
            m_outStr.WriteByte((byte)(0xE0 | partialPower));
            m_outStr.Write(partialBuffer, 0, partialBufferLength);
            partialOffset = 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void PartialFlush(ref ReadOnlySpan<byte> buffer)
        {
            m_outStr.WriteByte((byte)(0xE0 | partialPower));
            m_outStr.Write(buffer[..partialBufferLength]);
            buffer = buffer[partialBufferLength..];
        }
#endif

        private void PartialFlushLast()
        {
            StreamUtilities.WriteNewPacketLength(m_outStr, partialOffset);
            m_outStr.Write(partialBuffer, 0, partialOffset);
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
                m_outStr.Write(buffer, offset, count);
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
                m_outStr.Write(buffer);
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
                m_outStr.WriteByte(value);
            }
        }

        public void WritePacket(ContainedPacket p) => p.Encode(this);

        /// <summary>
        /// Write a packet, with the packet format chosen primarily based on <see cref="m_packetFormat"/>.
        /// </summary>
        /// <remarks>
        /// If <see cref="m_packetFormat"/> is <see cref="PacketFormat.Current"/>, the packet will be encoded using the
        /// new format. If it is <see cref="PacketFormat.Legacy"/>, the packet will use the old encoding format. If it
        /// is <see cref="PacketFormat.Roundtrip"/>, then the format will be determined by
        /// <paramref name="objectPrefersNewPacketFormat">
        /// Whether the packet prefers to be encoded using the new packet format.
        /// </paramref>.
        /// <paramref name="tag">The packet tag.</paramref>
        /// <paramref name="body">The packet body.</paramref>
        /// </remarks>
        /// <exception cref="IOException"
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void WritePacket(bool objectPrefersNewPacketFormat, PacketTag tag, ReadOnlySpan<byte> body)
#else
        internal void WritePacket(bool objectPrefersNewPacketFormat, PacketTag tag, byte[] body)
#endif
        {
            WritePacketHeader(objectPrefersNewPacketFormat, tag, body.Length);
            Write(body);
        }

        /// <summary>Write a packet, forcing the packet format to be either old or new.</summary>
        /// <paramref name="tag">The packet tag.</paramref>
        /// <paramref name="body">The packet body.</paramref>
        /// <param name="oldFormat">If <c>true</c>, old format is forced, else force new format.</param>
        /// <exception cref="IOException"
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void WritePacket(PacketTag tag, ReadOnlySpan<byte> body, bool oldFormat)
#else
        internal void WritePacket(PacketTag tag, byte[] body, bool oldFormat)
#endif
        {
            WriteHeader(tag, oldFormat, partial: false, body.Length);
            Write(body);
        }

        internal void WritePacketHeader(bool objectPrefersNewPacketFormat, PacketTag tag, long bodyLength)
        {
            bool oldPacketFormat = m_packetFormat == PacketFormat.Legacy ||
                (m_packetFormat == PacketFormat.Roundtrip && !objectPrefersNewPacketFormat);
            WriteHeader(tag, oldPacketFormat, false, bodyLength);
        }

        public void WriteObject(BcpgObject bcpgObject) => bcpgObject.Encode(this);

        public void WriteObjects(params BcpgObject[] v)
        {
            foreach (BcpgObject o in v)
            {
                o.Encode(this);
            }
        }

        /// <summary>Flush the underlying stream.</summary>
        public override void Flush() => m_outStr.Flush();

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
                Finish();
                m_outStr.Flush();
                m_outStr.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <exception cref="IOException"/>
        internal static byte[] GetEncoded(BcpgObject bcpgObject)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                bcpgObject.Encode(pOut);
            }
            return bOut.ToArray();
        }

        internal static byte[] GetEncodedOrNull(BcpgObject bcpgObject)
        {
            try
            {
                return GetEncoded(bcpgObject);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
