using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Class for processing literal data objects.</summary>
    public class PgpLiteralData
        : PgpObject
    {
        /// <summary>Format tag for binary literal data.</summary>
        public const char Binary = 'b';
        /// <summary>Format tag for textual literal data.</summary>
        public const char Text = 't';
        /// <summary>Format tag for UTF-8 encoded textual literal data.</summary>
        public const char Utf8 = 'u';
        /// <summary>Format tag for MIME message bodies.</summary>
        public const char Mime = 'm';

        /// <summary>The special name indicating a "for your eyes only" packet.</summary>
        public const string Console = "_CONSOLE";

        /// <summary>The special time for a modification time of "now" or the present time.</summary>
        // TODO Using an actual DateTime to represent this "semantic now" feels unsatisfactory
        public static readonly DateTime Now = DateTimeUtilities.UnixEpoch;

        private readonly LiteralDataPacket m_data;

        /// <summary>Construct a PGP LiteralData carrier from the passed in byte array.</summary>
        /// <param name="encData">an encoding of PGP literal data.</param>
        /// <exception cref="IOException">if an error occurs reading from the PGP input.</exception>
        public PgpLiteralData(byte[] encData)
            : this(Utilities.CreateBcpgInputStream(new MemoryStream(encData, false), PacketTag.LiteralData))
        {
        }

        /// <summary>Construct a PGP LiteralData carrier from the passed in input stream.</summary>
        /// <param name="inStream">an input stream containing an encoding of PGP literal data.</param>
        /// <exception cref="IOException">if an error occurs reading from the PGP input.</exception>
        public PgpLiteralData(Stream inStream)
            : this(Utilities.CreateBcpgInputStream(inStream, PacketTag.LiteralData))
        {
        }

        /// <summary>Construct a PGP LiteralData carrier from the passed in BCPG input stream.</summary>
        /// <param name="bcpgInput">a BCPG input stream containing an encoded PGP literal data structure.</param>
        /// <exception cref="IOException">if an error occurs reading from the PGP input.</exception>
        public PgpLiteralData(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is LiteralDataPacket literalDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            m_data = literalDataPacket;
        }

        /// <summary>The format of the data stream - Binary or Text</summary>
        public int Format => m_data.Format;

        /// <summary>The file name that's associated with the data stream.</summary>
        public string FileName => m_data.FileName;

        /// Return the file name as an unintrepreted byte array.
        public byte[] GetRawFileName() => m_data.GetRawFileName();

        /// <summary>The modification time for the file.</summary>
        public DateTime ModificationTime => DateTimeUtilities.UnixMsToDateTime(m_data.ModificationTime);

        /// <summary>The raw input stream for the data stream.</summary>
        public Stream GetInputStream() => m_data.GetInputStream();

        /// <summary>The input stream representing the data stream.</summary>
        public Stream GetDataStream() => GetInputStream();
    }
}
