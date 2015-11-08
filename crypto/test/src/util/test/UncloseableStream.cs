using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Utilities.Test
{
	public class UncloseableStream
		: FilterStream
	{
		public UncloseableStream(
			Stream s)
			: base(s)
		{
		}

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
			    throw new Exception("UncloseableStream was disposed");
            }

            base.Dispose(disposing);
        }
#else
        public override void Close()
		{
			throw new Exception("Close() called on UncloseableStream");
		}
#endif
    }
}
