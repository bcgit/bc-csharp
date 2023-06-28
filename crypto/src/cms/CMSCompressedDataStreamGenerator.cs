using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Utilities;
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

        private int _bufferSize;

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
			_bufferSize = bufferSize;
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

			BerSequenceGenerator sGen = new BerSequenceGenerator(outStream);

			sGen.AddObject(CmsObjectIdentifiers.CompressedData);

			//
			// Compressed Data
			//
			BerSequenceGenerator cGen = new BerSequenceGenerator(
				sGen.GetRawOutputStream(), 0, true);

			// CMSVersion
			cGen.AddObject(new DerInteger(0));

			// CompressionAlgorithmIdentifier
			cGen.AddObject(new AlgorithmIdentifier(CmsObjectIdentifiers.ZlibCompress));

			//
			// Encapsulated ContentInfo
			//
			BerSequenceGenerator eiGen = new BerSequenceGenerator(cGen.GetRawOutputStream());

			eiGen.AddObject(new DerObjectIdentifier(contentOid));

            BerOctetStringGenerator octGen = new BerOctetStringGenerator(eiGen.GetRawOutputStream(), 0, true);
            Stream octetStream = octGen.GetOctetOutputStream(_bufferSize);

            return new CmsCompressedOutputStream(
				Utilities.IO.Compression.ZLib.CompressOutput(octetStream, -1), sGen, cGen, eiGen, octGen);
		}

		private class CmsCompressedOutputStream
			: BaseOutputStream
		{
			private Stream _out;
			private BerSequenceGenerator _sGen;
			private BerSequenceGenerator _cGen;
			private BerSequenceGenerator _eiGen;
			private BerOctetStringGenerator _octGen;

            internal CmsCompressedOutputStream(
				Stream					outStream,
				BerSequenceGenerator	sGen,
				BerSequenceGenerator	cGen,
				BerSequenceGenerator	eiGen,
                BerOctetStringGenerator octGen)
			{
				_out = outStream;
				_sGen = sGen;
				_cGen = cGen;
				_eiGen = eiGen;
				_octGen = octGen;
			}

			public override void Write(byte[] buffer, int offset, int count)
			{
				_out.Write(buffer, offset, count);
			}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
			{
                _out.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
			{
				_out.WriteByte(value);
			}

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _out.Dispose();

					// TODO Parent context(s) should really be be closed explicitly

					_octGen.Dispose();
                    _eiGen.Dispose();
				    _cGen.Dispose();
				    _sGen.Dispose();
                }
                base.Dispose(disposing);
            }
		}
	}
}
