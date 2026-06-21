using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Streaming generator for CMS CompressedData messages. Call <see cref="Open(Stream)"/> to obtain a
    /// <see cref="Stream"/> to which the content to be compressed is written; closing that stream finalizes the
    /// CMS structure. Only ZLIB compression (<see cref="ZLib"/>) is supported.
    /// </summary>
    /// <remarks>
    /// The returned stream must be closed (disposed) to finalize the CMS structure. Closing the returned stream
    /// does <b>not</b> close the underlying stream passed to <c>Open</c>; callers are responsible for closing the
    /// underlying stream separately.
    /// <para>A simple example of usage:</para>
    /// <code>
    /// CmsCompressedDataStreamGenerator gen = new CmsCompressedDataStreamGenerator();
    /// using (Stream cOut = gen.Open(outputStream, CmsCompressedDataStreamGenerator.ZLib))
    /// {
    ///     cOut.Write(data, 0, data.Length);
    /// }
    /// </code>
    /// </remarks>
    public class CmsCompressedDataStreamGenerator
    {
        /// <summary>The OID for ZLIB compression, the only algorithm supported by this generator.</summary>
        public static readonly string ZLib = CmsObjectIdentifiers.ZlibCompress.Id;

        private int m_bufferSize;

        /// <summary>Creates a generator instance.</summary>
        public CmsCompressedDataStreamGenerator()
        {
        }

        /// <summary>
        /// Sets the buffer size used for the OCTET STRING segments holding the encapsulated content.
        /// </summary>
        /// <param name="bufferSize">The length, in bytes, of the octet strings used to buffer the data.</param>
        public void SetBufferSize(int bufferSize)
        {
            m_bufferSize = bufferSize;
        }

        /// <summary>
        /// Opens a stream for generating a CMS CompressedData object using ZLIB compression and content type "data".
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <returns>A stream the content to be compressed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream)
        {
            return Open(outStream, CmsObjectIdentifiers.Data.Id, ZLib);
        }

        /// <summary>
        /// Opens a stream for generating a CMS CompressedData object with content type "data".
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="compressionOid">The compression algorithm OID; must be <see cref="ZLib"/>.</param>
        /// <returns>A stream the content to be compressed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, string compressionOid)
        {
            return Open(outStream, CmsObjectIdentifiers.Data.Id, compressionOid);
        }

        /// <summary>
        /// Opens a stream for generating a CMS CompressedData object with the given encapsulated content type.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="contentOid">The OID of the content type being compressed.</param>
        /// <param name="compressionOid">The compression algorithm OID; must be <see cref="ZLib"/>.</param>
        /// <returns>A stream the content to be compressed is written to; close it to finalize the structure.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="compressionOid"/> is not ZLIB.</exception>
        public Stream Open(Stream outStream, string contentOid, string compressionOid)
        {
            if (ZLib != compressionOid)
                throw new ArgumentException("Unsupported compression algorithm: " + compressionOid,
                    nameof(compressionOid));

            // ContentInfo
            BerSequenceGenerator sGen = new BerSequenceGenerator(outStream);
            sGen.AddObject(CmsObjectIdentifiers.CompressedData);

            // CompressedData
            BerSequenceGenerator cGen = new BerSequenceGenerator(sGen.GetRawOutputStream(), 0, true);
            cGen.AddObject(DerInteger.Zero);
            cGen.AddObject(new AlgorithmIdentifier(CmsObjectIdentifiers.ZlibCompress));

            // EncapsulatedContentInfo
            BerSequenceGenerator eciGen = new BerSequenceGenerator(cGen.GetRawOutputStream());
            eciGen.AddObject(new DerObjectIdentifier(contentOid));

            // eContent [0] EXPLICIT OCTET STRING OPTIONAL
            BerOctetStringGenerator ecGen = new BerOctetStringGenerator(eciGen.GetRawOutputStream(), 0, true);
            Stream ecStream = ecGen.GetOctetOutputStream(m_bufferSize);

            var compressedStream = Utilities.IO.Compression.ZLib.CompressOutput(ecStream, -1);

            return new CmsCompressedOutputStream(compressedStream, sGen, cGen, eciGen, ecGen);
        }

        private class CmsCompressedOutputStream
            : BaseOutputStream
        {
            private Stream m_out;
            private BerSequenceGenerator m_sGen;
            private BerSequenceGenerator m_cGen;
            private BerSequenceGenerator m_eciGen;
            private BerOctetStringGenerator m_ecGen;

            internal CmsCompressedOutputStream(Stream outStream, BerSequenceGenerator sGen, BerSequenceGenerator cGen,
                BerSequenceGenerator eciGen, BerOctetStringGenerator ecGen)
            {
                m_out = outStream;
                m_sGen = sGen;
                m_cGen = cGen;
                m_eciGen = eciGen;
                m_ecGen = ecGen;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                m_out.Write(buffer, offset, count);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                m_out.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
            {
                m_out.WriteByte(value);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    m_out.Dispose();

                    // TODO Parent context(s) should really be be closed explicitly

                    m_ecGen.Dispose();
                    m_eciGen.Dispose();
                    m_cGen.Dispose();
                    m_sGen.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }
}
