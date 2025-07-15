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

        private readonly Stream outStr;
        private readonly bool useOldFormat;
        private readonly int partialBufferLength;
        private readonly int partialPower;

        private byte[] partialBuffer;
        private int partialOffset;

        /// <summary>Create a stream representing a general packet.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        public BcpgOutputStream(Stream outStr)
            : this(outStr, newFormatOnly: false)
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

            WriteHeader(tag, oldFormat: true, partial: true, 0);
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
                WriteHeader(tag, oldFormat: false, partial: true, 0);

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
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));

            WriteHeader(tag, oldFormat: false, partial: false, length);
        }

        /// <summary>Create a new style partial input stream buffered into chunks.</summary>
        /// <param name="outStr">Output stream to write to.</param>
        /// <param name="tag">Packet tag.</param>
        /// <param name="buffer">Buffer to use for collecting chunks.</param>
        public BcpgOutputStream(Stream outStr, PacketTag tag, byte[] buffer)
        {
            this.outStr = outStr ?? throw new ArgumentNullException(nameof(outStr));

            WriteHeader(tag, oldFormat: false, partial: true, 0);

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
                        WriteByte((byte)(bodyLen >> 8));
                        WriteByte((byte)(bodyLen));
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
                        WriteByte((byte)(bodyLen >> 24));
                        WriteByte((byte)(bodyLen >> 16));
                        WriteByte((byte)(bodyLen >> 8));
                        WriteByte((byte)bodyLen);
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
                    StreamUtilities.WriteNewPacketLength(outStr, bodyLen);
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
            StreamUtilities.WriteNewPacketLength(outStr, partialOffset);
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

        public void WritePacket(ContainedPacket p) => p.Encode(this);

        internal void WritePacket(PacketTag tag, byte[] body) => WritePacket(tag, body, useOldFormat);

        internal void WritePacket(PacketTag tag, byte[] body, bool oldFormat)
        {
            WriteHeader(tag, oldFormat, partial: false, body.Length);
            Write(body);
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
        public override void Flush() => outStr.Flush();

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
                outStr.Flush();
                outStr.Dispose();
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
