using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Reader for PGP objects.</remarks>
    public class BcpgInputStream
        : BaseInputStream
    {
        private Stream m_in;
        private bool next = false;
        private int nextB;

        internal static BcpgInputStream Wrap(Stream inStr)
        {
            if (inStr is BcpgInputStream bcpg)
                return bcpg;

            return new BcpgInputStream(inStr);
        }

        private BcpgInputStream(
			Stream inputStream)
        {
            this.m_in = inputStream;
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

            bool newPacket = (hdr & 0x40) != 0;
            PacketTag tag = 0;
            uint bodyLen;
            bool partial = false;

            if (newPacket)
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
                    bodyLen = 0;
                    partial = true;
                    break;
                default:
                    throw new IOException("unknown length type encountered");
                }
            }

            BcpgInputStream objStream;
            if (bodyLen == 0 && partial)
            {
                objStream = this;
            }
            else
            {
                PartialInputStream pis = new PartialInputStream(this, partial, bodyLen);
				Stream buf = new BufferedStream(pis);
                objStream = new BcpgInputStream(buf);
            }

            switch (tag)
            {
            case PacketTag.Reserved:
                return new InputStreamPacket(objStream);
            case PacketTag.PublicKeyEncryptedSession:
                return new PublicKeyEncSessionPacket(objStream);
            case PacketTag.Signature:
                return new SignaturePacket(objStream);
            case PacketTag.SymmetricKeyEncryptedSessionKey:
                return new SymmetricKeyEncSessionPacket(objStream);
            case PacketTag.OnePassSignature:
                return new OnePassSignaturePacket(objStream);
            case PacketTag.SecretKey:
                return new SecretKeyPacket(objStream);
            case PacketTag.PublicKey:
                return new PublicKeyPacket(objStream);
            case PacketTag.SecretSubkey:
                return new SecretSubkeyPacket(objStream);
            case PacketTag.CompressedData:
                return new CompressedDataPacket(objStream);
            case PacketTag.SymmetricKeyEncrypted:
                return new SymmetricEncDataPacket(objStream);
            case PacketTag.Marker:
                return new MarkerPacket(objStream);
            case PacketTag.LiteralData:
                return new LiteralDataPacket(objStream);
            case PacketTag.Trust:
                return new TrustPacket(objStream);
            case PacketTag.UserId:
                return new UserIdPacket(objStream);
            case PacketTag.UserAttribute:
                return new UserAttributePacket(objStream);
            case PacketTag.PublicSubkey:
                return new PublicSubkeyPacket(objStream);
            case PacketTag.SymmetricEncryptedIntegrityProtected:
                return new SymmetricEncIntegrityPacket(objStream);
            case PacketTag.ModificationDetectionCode:
                return new ModDetectionCodePacket(objStream);
            case PacketTag.Experimental1:
            case PacketTag.Experimental2:
            case PacketTag.Experimental3:
            case PacketTag.Experimental4:
                return new ExperimentalPacket(tag, objStream);
            default:
                throw new IOException("unknown packet type encountered: " + tag);
            }
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
		/// If partial is true, dataLength should only be up to 2^30 bytes.
		/// Otherwise it's a non-partial packet and can be larger.
		/// </summary>
		private class PartialInputStream
            : BaseInputStream
        {
            private BcpgInputStream m_in;
            private bool partial;
            private uint dataLength;

            internal PartialInputStream(
                BcpgInputStream	bcpgIn,
                bool			partial,
                uint			dataLength)
            {
                this.m_in = bcpgIn;
                this.partial = partial;
                this.dataLength = dataLength;
            }

			public override int ReadByte()
			{
				do
				{
					if (dataLength != 0)
					{
						int ch = m_in.ReadByte();
						if (ch < 0)
							throw new EndOfStreamException("Premature end of stream in PartialInputStream");

						dataLength--;
						return ch;
					}
				}
				while (partial && ReadPartialDataLength());

				return -1;
			}

			public override int Read(byte[] buffer, int offset, int count)
			{
                Streams.ValidateBufferArguments(buffer, offset, count);

				do
				{
					if (dataLength != 0)
					{
                        int readLen = (dataLength > count) ? count : (int)dataLength;
						int len = m_in.Read(buffer, offset, readLen);
						if (len < 1)
							throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        dataLength = (uint)(dataLength - len);
						return len;
					}
				}
				while (partial && ReadPartialDataLength());

				return 0;
			}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer)
            {
				do
				{
					if (dataLength != 0)
					{
                        int count = buffer.Length;
                        int readLen = (dataLength > count) ? count : (int)dataLength;
						int len = m_in.Read(buffer[..readLen]);
						if (len < 1)
							throw new EndOfStreamException("Premature end of stream in PartialInputStream");

                        dataLength = (uint)(dataLength - len);
						return len;
					}
				}
				while (partial && ReadPartialDataLength());

				return 0;
            }
#endif

            private bool ReadPartialDataLength()
            {
                uint? bodyLen = StreamUtilities.ReadBodyLen(m_in, out var streamFlags);
                // If we can't read the body length, or it's too large, we can't continue
                // reading the stream as a partial stream, because partials only support up to 2^30
                if (!bodyLen.HasValue || bodyLen > (1U << 30))
                {
                    partial = false;
                    dataLength = 0;
                    return false;
                }

                partial = streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial);
                dataLength = bodyLen.Value;
                return true;
            }
        }
    }
}
