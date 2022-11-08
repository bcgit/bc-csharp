using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	internal sealed class WrappedGeneratorStream
		: FilterStream
	{
		private readonly IStreamGenerator m_generator;

		internal WrappedGeneratorStream(IStreamGenerator generator, Stream s)
			: base(s)
		{
			m_generator = generator ?? throw new ArgumentNullException(nameof(generator));
		}

        protected override void Dispose(bool disposing)
        {
			if (disposing)
			{
				m_generator.Dispose();
			}

			Detach(disposing);
		}
	}
}
