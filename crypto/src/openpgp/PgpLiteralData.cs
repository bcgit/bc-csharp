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

        private readonly LiteralDataPacket m_data;

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
