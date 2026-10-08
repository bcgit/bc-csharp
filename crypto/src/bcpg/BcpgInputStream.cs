using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Reader for PGP objects.</remarks>
    // TODO[api] Make sealed
    public class BcpgInputStream
        : BaseInputStream
    {
        private readonly Stream m_in;
        private bool next = false;
        private int nextB;

        internal static BcpgInputStream Wrap(Stream inStr)
        {
            if (inStr is BcpgInputStream bcpg)
                return bcpg;

            return new BcpgInputStream(inStr);
        }

        public BcpgInputStream(Stream inputStream)
        {
            m_in = inputStream;
        }

        public override int ReadByte()
        {
            if (next)
            {
                next = false;
                return nextB;
            }

            return m_in.ReadByte();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!next)
                return m_in.Read(buffer, offset, count);

            Streams.ValidateBufferArguments(buffer, offset, count);

            if (nextB < 0)
                return 0;

            buffer[offset] = (byte)nextB;
            next = false;
            return 1;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            if (!next)
                return m_in.Read(buffer);

            if (nextB < 0)
                return 0;

            buffer[0] = (byte)nextB;
            next = false;
            return 1;
        }
#endif

        public byte[] ReadAll() => Streams.ReadAll(this);

        public void ReadFully(byte[] buffer, int offset, int count) =>
            StreamUtilities.RequireBytes(this, buffer, offset, count);

        public void ReadFully(byte[] buffer) => StreamUtilities.RequireBytes(this, buffer);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ReadFully(Span<byte> buffer) => StreamUtilities.RequireBytes(this, buffer);
#endif

        public byte RequireByte() => StreamUtilities.RequireByte(this);

        /// <summary>Returns the next packet tag in the stream.</summary>
        public PacketTag NextPacketTag()
        {
            if (!next)
            {
                try
                {
                    nextB = m_in.ReadByte();
                }
                catch (EndOfStreamException)
                {
                    nextB = -1;
                }

                next = true;
            }

            if (nextB < 0)
                return (PacketTag)nextB;

            int maskB = nextB & 0x3f;
            if ((nextB & 0x40) == 0)    // old
            {
                maskB >>= 2;
            }
            return (PacketTag)maskB;
        }

        public Packet ReadPacket()
        {
            int hdr = ReadByte();
            if (hdr < 0)
                return null;

            if ((hdr & 0x80) == 0)
                throw new IOException("invalid header encountered");

            bool newPacketFormat = (hdr & 0x40) != 0;
            PacketTag tag = 0;

            uint bodyLen;
            bool partial = false;

            if (newPacketFormat)
            {
                tag = (PacketTag)(hdr & 0x3f);
                bodyLen = StreamUtilities.RequireBodyLen(this, out var streamFlags);
                partial = streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial);
            }
            else
            {
                int lengthType = hdr & 0x3;

                tag = (PacketTag)((hdr & 0x3f) >> 2);

                switch (lengthType)
                {
                case 0:
                    bodyLen = StreamUtilities.RequireByte(this);
                    break;
                case 1:
                    bodyLen = StreamUtilities.RequireUInt16BE(this);
                    break;
                case 2:
                    bodyLen = StreamUtilities.RequireUInt32BE(this);
                    break;
                case 3:
                    bodyLen = 0U;
                    partial = true;
                    break;
                default:
                    throw new IOException("unknown length type encountered");
                }
            }

            BcpgInputStream objStream;
            if (bodyLen == 0U && partial)
            {
                objStream = this;
            }
            else
            {
                Debug.Assert(!this.next);
                PartialInputStream pis = new PartialInputStream(m_in, partial, bodyLen);
                objStream = new BcpgInputStream(new BufferedStream(pis));
            }

            switch (tag)
            {
            case PacketTag.Reserved:
                return new ReservedPacket(objStream, newPacketFormat);
            case PacketTag.PublicKeyEncryptedSession:
                return new PublicKeyEncSessionPacket(objStream, newPacketFormat);
            case PacketTag.Signature:
                // RFC 9580 5.2.5: a malformed signature does not halt processing, so the rest of its packet is
                // consumed (a stream that ends early still throws)
                try
                {
                    var signature = new SignaturePacket(objStream, newPacketFormat);
                    // RFC 9580 4.2.1.4: partial lengths are only for data packets
                    // TODO[api] Also for version 4 signatures
                    if (partial && signature.Version == SignaturePacket.Version6)
                    {
                        signature.MarkMalformed();
                    }
                    return signature;
                }
                catch (Exception e) when (objStream != this && (e is IOException || e is ArgumentException))
                {
                    Streams.Drain(objStream);
                    throw new MalformedSignaturePacketException("malformed signature packet: " + e.Message, e);
                }
            case PacketTag.SymmetricKeyEncryptedSessionKey:
                return new SymmetricKeyEncSessionPacket(objStream, newPacketFormat);
            case PacketTag.OnePassSignature:
                // RFC 9580 5.2.5: a malformed one-pass signature does not halt processing either
                try
                {
                    var onePass = new OnePassSignaturePacket(objStream, newPacketFormat);
                    // RFC 9580 5.4, 4.2.1.4: nothing follows the nested flag, and partial lengths are only for
                    // data packets
                    // TODO[api] Also for version 3 one-pass signatures
                    if (onePass.Version == OnePassSignaturePacket.Version6 &&
                        (partial || (objStream != this && objStream.ReadByte() >= 0)))
                    {
                        throw new MalformedPacketException("Malformed version 6 one-pass signature.");
                    }
                    return onePass;
                }
                catch (Exception e) when (objStream != this && (e is IOException || e is ArgumentException))
                {
                    Streams.Drain(objStream);
                    throw new MalformedSignaturePacketException("malformed one-pass signature packet: " + e.Message,
                        e);
                }
            case PacketTag.SecretKey:
            {
                var secretKey = new SecretKeyPacket(objStream, newPacketFormat);
                return RequireDefiniteLength(secretKey, secretKey.PublicKeyPacket, partial);
            }
            case PacketTag.PublicKey:
            {
                var publicKey = new PublicKeyPacket(objStream, newPacketFormat);
                return RequireDefiniteLength(publicKey, publicKey, partial);
            }
            case PacketTag.SecretSubkey:
            {
                var secretSubkey = new SecretSubkeyPacket(objStream, newPacketFormat);
                return RequireDefiniteLength(secretSubkey, secretSubkey.PublicKeyPacket, partial);
            }
            case PacketTag.CompressedData:
                return new CompressedDataPacket(objStream, newPacketFormat);
            case PacketTag.SymmetricKeyEncrypted:
                return new SymmetricEncDataPacket(objStream, newPacketFormat);
            case PacketTag.Marker:
                return new MarkerPacket(objStream, newPacketFormat);
            case PacketTag.LiteralData:
                return new LiteralDataPacket(objStream, newPacketFormat);
            case PacketTag.Trust:
                return new TrustPacket(objStream, newPacketFormat);
            case PacketTag.UserId:
                return new UserIdPacket(objStream, newPacketFormat);
            case PacketTag.UserAttribute:
                return new UserAttributePacket(objStream, newPacketFormat);
            case PacketTag.PublicSubkey:
            {
                var publicSubkey = new PublicSubkeyPacket(objStream, newPacketFormat);
                return RequireDefiniteLength(publicSubkey, publicSubkey, partial);
            }
            case PacketTag.SymmetricEncryptedIntegrityProtected:
                return new SymmetricEncIntegrityPacket(objStream, newPacketFormat);
            case PacketTag.ModificationDetectionCode:
                return new ModDetectionCodePacket(objStream, newPacketFormat);
            case PacketTag.AeadEncData:
                return new AeadEncDataPacket(objStream, newPacketFormat);
            case PacketTag.Padding:
                return new PaddingPacket(objStream, newPacketFormat);
            case PacketTag.Experimental1:
            case PacketTag.Experimental2:
            case PacketTag.Experimental3:
            case PacketTag.Experimental4:
                return new ExperimentalPacket(tag, objStream, newPacketFormat);
            default:
                return new UnknownPacket(tag, objStream, newPacketFormat);
            }
        }

        /// <summary>
        /// RFC 9580 4.2.1.4: partial lengths are only for data packets, so a version 6 key packet with them is
        /// malformed.
        /// </summary>
        // TODO[api] Also for key packets of other versions
        private static Packet RequireDefiniteLength(Packet packet, PublicKeyPacket key, bool partial)
        {
            if (partial && key.Version == PublicKeyPacket.Version6)
                throw new MalformedPacketException("Partial lengths in a version 6 key packet.");

            return packet;
        }

        public PacketTag SkipMarkerPackets()
        {
            PacketTag tag;
            while ((tag = NextPacketTag()) == PacketTag.Marker)
            {
                ReadPacket();
            }

            return tag;
        }

        /// <summary>
        /// Consume any Marker and Padding packets, and packets of the non-critical types (40 to 63), which are
        /// ignored within packet sequences (RFC 9580 4.3, 5.8, 5.14), and return the tag of the next packet.
        /// </summary>
        internal PacketTag SkipIgnoredPackets()
        {
            PacketTag tag;
            while ((tag = NextPacketTag()) == PacketTag.Marker || tag == PacketTag.Padding || (int)tag >= 40)
            {
                ReadPacket();
            }

            return tag;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_in.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// A stream that overlays our input stream, allowing the user to only read a segment of it.
        /// </summary>
        /// <remarks>
        /// If <c>partial</c> is <c>true</c>, <c>dataLength</c> should only be up to 2^30 bytes. Otherwise it's a
        /// non-partial packet and can be larger.
        /// </remarks>
        private class PartialInputStream
            : BaseInputStream
        {
            private readonly Stream m_in;
            private bool m_partial;
            private uint m_dataLength;

            internal PartialInputStream(Stream inStr, bool partial, uint dataLength)
            {
                m_in = inStr;
                m_partial = partial;
                m_dataLength = dataLength;
            }

            public override int ReadByte()
            {
                do
                {
                    if (m_dataLength > 0U)
                    {
                        int ch = m_in.ReadByte();
                        if (ch < 0)
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        --m_dataLength;
                        return ch;
                    }
                }
                while (m_partial && ReadPartialDataLength());

                return -1;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

                do
                {
                    if (m_dataLength > 0U)
                    {
                        int readLen = (uint)count < m_dataLength ? count : (int)m_dataLength;
                        int len = m_in.Read(buffer, offset, readLen);
                        if (len < 1)
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        m_dataLength -= (uint)len;
                        return len;
                    }
                }
                while (m_partial && ReadPartialDataLength());

                return 0;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer)
            {
                do
                {
                    if (m_dataLength > 0U)
                    {
                        int count = buffer.Length;
                        int readLen = (uint)count < m_dataLength ? count : (int)m_dataLength;
                        int len = m_in.Read(buffer[..readLen]);
                        if (len < 1)
                            throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        m_dataLength -= (uint)len;
                        return len;
                    }
                }
                while (m_partial && ReadPartialDataLength());

                return 0;
            }
#endif

            private bool ReadPartialDataLength()
            {
                // RFC 9580 4.2.1.4: a packet with partial lengths ends with a definite length, so the end of the
                // stream before it truncates the packet
                uint bodyLen = StreamUtilities.ReadBodyLen(m_in, out var streamFlags);
                if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Eof))
                    throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                m_partial = streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial);
                m_dataLength = bodyLen;
                return true;
            }
        }
    }
}
