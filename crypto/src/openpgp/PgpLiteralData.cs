using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <summary>Class for processing literal data objects.</summary>
    public class PgpLiteralData
		: PgpObject
    {
        public const char Binary = 'b';
        public const char Text = 't';
		public const char Utf8 = 'u';

		/// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = "_CONSOLE";

		private readonly LiteralDataPacket data;

		public PgpLiteralData(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is LiteralDataPacket literalDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.data = literalDataPacket;
        }

		/// <summary>The format of the data stream - Binary or Text</summary>
        public int Format
        {
            get { return data.Format; }
        }

		/// <summary>The file name that's associated with the data stream.</summary>
        public string FileName
        {
			get { return data.FileName; }
        }

		/// Return the file name as an unintrepreted byte array.
		public byte[] GetRawFileName()
		{
			return data.GetRawFileName();
		}

		/// <summary>The modification time for the file.</summary>
        public DateTime ModificationTime
        {
			get { return DateTimeUtilities.UnixMsToDateTime(data.ModificationTime); }
        }

		/// <summary>The raw input stream for the data stream.</summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

		/// <summary>The input stream representing the data stream.</summary>
        public Stream GetDataStream()
        {
            return GetInputStream();
        }

        /// <summary>
        /// Additional metadata for v5 signatures
        /// https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures
        /// Only for document signatures (type 0x00 or 0x01) the following three data items are hashed:
        ///   * the one-octet content format,
        ///   * the file name as a string (one octet length, followed by the file name)
        ///   * a four-octet number that indicates a date,
        /// The three data items hashed for document signatures need to mirror the values of the
        /// Literal Data packet.
        /// For detached and cleartext signatures 6 zero bytes are hashed instead.
        /// </summary>
        /// <param name="sigVersion">Signature version</param>
        /// <returns></returns>
        public byte[] GetMetadata(int sigVersion)
        {
            // only v5 signatures requires additional metadata
            if (sigVersion != SignaturePacket.Version5)
            {
                return Array.Empty<byte>();
            }

            using (var ms = new MemoryStream())
            {
                byte[] rawFileName = data.GetRawFileName();
                long modTime = data.ModificationTime / 1000;
                ms.WriteByte((byte)Format);
                ms.WriteByte((byte)rawFileName.Length);
                ms.Write(rawFileName, 0, rawFileName.Length);

                ms.WriteByte((byte)(modTime >> 24));
                ms.WriteByte((byte)(modTime >> 16));
                ms.WriteByte((byte)(modTime >> 8));
                ms.WriteByte((byte)modTime);

                return ms.ToArray();
            }
        }
    }
}
