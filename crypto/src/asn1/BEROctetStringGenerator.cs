using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
	public class BerOctetStringGenerator
		: BerGenerator
	{
		public BerOctetStringGenerator(Stream outStream)
			: base(outStream)
		{
			WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.OctetString);
		}

		public BerOctetStringGenerator(
			Stream	outStream,
			int		tagNo,
			bool	isExplicit)
			: base(outStream, tagNo, isExplicit)
		{
			WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.OctetString);
		}

		public Stream GetOctetOutputStream()
		{
			return GetOctetOutputStream(new byte[1000]); // limit for CER encoding.
		}

		public Stream GetOctetOutputStream(
			int bufSize)
		{
			return bufSize < 1
				?	GetOctetOutputStream()
				:	GetOctetOutputStream(new byte[bufSize]);
		}

		public Stream GetOctetOutputStream(
			byte[] buf)
		{
			return new BufferedBerOctetStream(this, buf);
		}

		private class BufferedBerOctetStream
			: BaseOutputStream
		{
			private byte[] _buf;
			private int    _off;
			private readonly BerOctetStringGenerator _gen;
			private readonly Asn1OutputStream _derOut;

			internal BufferedBerOctetStream(
				BerOctetStringGenerator	gen,
				byte[]					buf)
			{
				_gen = gen;
				_buf = buf;
				_off = 0;
				_derOut = Asn1OutputStream.Create(_gen.Out, Asn1Encodable.Der);
			}

			public override void WriteByte(
				byte b)
			{
				_buf[_off++] = b;

				if (_off == _buf.Length)
				{
					DerOctetString.Encode(_derOut, true, _buf, 0, _off);
					_off = 0;
				}
			}

			public override void Write(byte[] b, int off, int len)
			{
                int bufLen = _buf.Length;
                int available = bufLen - _off;
                if (len < available)
                {
                    Array.Copy(b, off, _buf, _off, len);
                    _off += len;
                    return;
                }

                int count = 0;
                if (_off > 0)
                {
                    Array.Copy(b, off, _buf, _off, available);
                    count += available;
                    DerOctetString.Encode(_derOut, true, _buf, 0, bufLen);
                }

                int remaining;
                while ((remaining = len - count) >= bufLen)
                {
                    DerOctetString.Encode(_derOut, true, b, off + count, bufLen);
                    count += bufLen;
                }

                Array.Copy(b, off + count, _buf, 0, remaining);
                this._off = remaining;
            }

#if PORTABLE
            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
				    if (_off != 0)
				    {
					    DerOctetString.Encode(_derOut, true, _buf, 0, _off);
				    }

                    _derOut.FlushInternal();

				    _gen.WriteBerEnd();
                }
                base.Dispose(disposing);
            }
#else
            public override void Close()
			{
				if (_off != 0)
				{
					DerOctetString.Encode(_derOut, true, _buf, 0, _off);
				}

                _derOut.FlushInternal();

                _gen.WriteBerEnd();
				base.Close();
			}
#endif
		}
	}
}
