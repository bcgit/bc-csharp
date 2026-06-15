using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Compressed data objects</remarks>
    public class PgpCompressedData
        : PgpObject
    {
        private readonly CompressedDataPacket m_data;

        public PgpCompressedData(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is CompressedDataPacket compressedDataPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            m_data = compressedDataPacket;
        }

        /// <summary>The algorithm used for compression</summary>
        public CompressionAlgorithmTag Algorithm => m_data.Algorithm;

        /// <summary>Get the raw input stream contained in the object.</summary>
        public Stream GetInputStream() => m_data.GetInputStream();

        /// <summary>
        /// Return an input stream that decompresses and returns data in the compressed packet.
        /// </summary>
        /// <remarks>
        /// The OpenPGP compressed data packet carries no decompressed-length field, so the returned stream is
        /// unbounded; a small compressed packet can expand into an arbitrarily large amount of data (a "decompression
        /// bomb"). When processing untrusted input, a caller that buffers the full decompressed output should bound it,
        /// either by reading incrementally, or by using <see cref="GetDataStream(long)"/> to cap the number of
        /// decompressed bytes.
        /// </remarks>
        public Stream GetDataStream() => CreateDataStream();

        /// <summary>
        /// Return an input stream that decompresses and returns data in the compressed packet, failing with a
        /// <see cref="StreamOverflowException"/> (an <see cref="IOException"/>) once more than <paramref name="limit"/>
        /// decompressed bytes have been read. This caps the "decompression bomb" amplification of an untrusted
        /// compressed packet for callers that buffer the decompressed output.
        /// </summary>
        /// <remarks>
        /// The limit applies to the decompressed byte count. For BZip2 the underlying decompressor still allocates its
        /// fixed working buffers - sized by the packet's block-size header, up to ~4.5MB - when the stream is
        /// constructed, independently of this limit.
        /// </remarks>
        /// <param name="limit">
        /// The maximum number of decompressed bytes that may be read, or a negative value for no limit (equivalent to
        /// <see cref="GetDataStream()"/>).
        /// </param>
        /// <returns>
        /// A <see cref="Stream"/> over the uncompressed data, bounded to <paramref name="limit"/> bytes.
        /// </returns>
        public Stream GetDataStream(long limit)
        {
            var dataStream = CreateDataStream();

            if (limit < 0L)
                return dataStream;

            return new LimitedDecompressionStream(dataStream, limit);
        }

        private Stream CreateDataStream()
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

        // TODO Investigate consolidation with Utilities.IO.LimitedInputStream
        private class LimitedDecompressionStream
            : BaseInputStream
        {
            private readonly Stream m_stream;
            private long m_limit;

            internal LimitedDecompressionStream(Stream stream, long limit)
            {
                m_stream = stream;
                m_limit = limit;
            }

            public override int ReadByte()
            {
                // Only a single 'extra' byte will ever be read
                if (m_limit >= 0)
                {
                    int b = m_stream.ReadByte();
                    if (b < 0 || --m_limit >= 0)
                        return b;
                }

                throw new StreamOverflowException("decompressed data limit exceeded");
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return Read(buffer.AsSpan(offset, count));
#else
                // This will give correct exceptions/returns for strange lengths
                if (count < 1)
                    return m_stream.Read(buffer, offset, count);

                if (m_limit < 1)
                {
                    // Will either return EOF or throw exception
                    ReadByte();
                    return 0;
                }

                /*
                 * Limit the underlying request to 'm_limit' bytes. This ensures the caller will see the full 'limit'
                 * bytes before getting an exception. Also, only one extra byte will ever be read.
                 */
                int toRead = (int)System.Math.Min(m_limit, count);
                int numRead = m_stream.Read(buffer, offset, toRead);
                if (numRead > 0)
                {
                    m_limit -= numRead;
                }
                return numRead;
#endif
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer)
            {
                // This will give correct exceptions/returns for strange lengths
                if (buffer.Length < 1)
                    return m_stream.Read(buffer);

                if (m_limit < 1)
                {
                    // Will either return EOF or throw exception
                    ReadByte();
                    return 0;
                }

                /*
                 * Limit the underlying request to 'm_limit' bytes. This ensures the caller will see the full 'limit'
                 * bytes before getting an exception. Also, only one extra byte will ever be read.
                 */
                int toRead = (int)System.Math.Min(m_limit, buffer.Length);
                int numRead = m_stream.Read(buffer[..toRead]);
                if (numRead > 0)
                {
                    m_limit -= numRead;
                }
                return numRead;
            }
#endif
        }
    }
}
