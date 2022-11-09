using System.IO;

using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Compressed data objects</remarks>
    public class PgpCompressedData
		: PgpObject
    {
        private readonly CompressedDataPacket data;

		public PgpCompressedData(
            BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is CompressedDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            this.data = (CompressedDataPacket)packet;
        }

		/// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm
        {
			get { return data.Algorithm; }
        }

		/// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream()
        {
            return data.GetInputStream();
        }

		/// <summary>Return an uncompressed input stream which allows reading of the compressed data.</summary>
        public Stream GetDataStream()
        {
            switch (Algorithm)
            {
			case CompressionAlgorithmTag.Uncompressed:
				return GetInputStream();
			case CompressionAlgorithmTag.Zip:
                return Zip.DecompressInput(GetInputStream());
            case CompressionAlgorithmTag.ZLib:
				return ZLib.DecompressInput(GetInputStream());
			case CompressionAlgorithmTag.BZip2:
                return Bzip2.DecompressInput(GetInputStream());
            default:
                throw new PgpException("can't recognise compression algorithm: " + Algorithm);
            }
        }
    }
}
