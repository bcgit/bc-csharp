using System;
using System.IO;

using Org.BouncyCastle.Utilities.Zlib;

namespace Org.BouncyCastle.Crypto.Tls
{
	public class TlsDeflateCompression
		: TlsCompression
	{
		protected ZStream zIn, zOut;

		public TlsDeflateCompression()
		{
			this.zIn = new ZStream();
			this.zIn.inflateInit();

			this.zOut = new ZStream();
			// TODO Allow custom setting
			this.zOut.deflateInit(JZlib.Z_DEFAULT_COMPRESSION);
		}

		public virtual Stream Compress(Stream output)
		{
			return new DeflateOutputStream(output, zOut, true);
		}

		public virtual Stream Decompress(Stream output)
		{
			return new DeflateOutputStream(output, zIn, false);
		}

		protected class DeflateOutputStream : ZOutputStream
		{
			public DeflateOutputStream(Stream output, ZStream z, bool compress)
				: base(output)
			{
				this.z = z;
				this.compress = compress;
                // TODO http://www.bolet.org/~pornin/deflate-flush.html says we should use Z_SYNC_FLUSH
				this.FlushMode = JZlib.Z_PARTIAL_FLUSH;
			}
		}
	}
}
