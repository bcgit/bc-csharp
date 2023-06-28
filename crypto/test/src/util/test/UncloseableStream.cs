using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Utilities.Test
{
    /// <summary>
    /// This is a testing utility class to check the property that a <see cref="Stream"/> is never disposed in some
    /// particular context,typically when wrapped by another <see cref="Stream"/> that should not be forwarding its
    /// <see cref="IDisposable.Dispose"/> calls. Not needed in production code.
    /// </summary>
	public class UncloseableStream
		: FilterStream
	{
		public UncloseableStream(Stream s)
			: base(s)
		{
		}

        protected override void Dispose(bool disposing)
        {
            if (disposing)
			    throw new InvalidOperationException("UncloseableStream was disposed");

            base.Dispose(disposing);
        }
    }
}
