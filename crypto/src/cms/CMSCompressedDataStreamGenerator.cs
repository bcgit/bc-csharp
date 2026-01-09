using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /**
     * General class for generating a compressed CMS message stream.
     * <p>
     * A simple example of usage.
     * </p>
     * <pre>
     *      CMSCompressedDataStreamGenerator gen = new CMSCompressedDataStreamGenerator();
     *
     *      Stream cOut = gen.Open(outputStream, CMSCompressedDataStreamGenerator.ZLIB);
     *
     *      cOut.Write(data);
     *
     *      cOut.Close();
     * </pre>
     */
    public class CmsCompressedDataStreamGenerator
    {
        public static readonly string ZLib = CmsObjectIdentifiers.ZlibCompress.Id;

        private int m_bufferSize;

        /**
         * base constructor
         */
        public CmsCompressedDataStreamGenerator()
        {
        }

        /**
         * Set the underlying string size for encapsulated data
         *
         * @param bufferSize length of octet strings to buffer the data.
         */
        public void SetBufferSize(int bufferSize)
        {
            m_bufferSize = bufferSize;
        }

        public Stream Open(Stream outStream)
        {
            return Open(outStream, CmsObjectIdentifiers.Data.Id, ZLib);
        }

        public Stream Open(Stream outStream, string compressionOid)
        {
            return Open(outStream, CmsObjectIdentifiers.Data.Id, compressionOid);
        }

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
