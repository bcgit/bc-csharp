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

		public override void Close()
		{
			throw new Exception("Close() called on UncloseableStream");
		}
	}
}
