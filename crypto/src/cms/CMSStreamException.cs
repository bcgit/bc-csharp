using System;
using System.IO;

namespace Org.BouncyCastle.Cms
{
#if !PORTABLE
    [Serializable]
#endif
    public class CmsStreamException
        : IOException
    {
		public CmsStreamException()
		{
		}

		public CmsStreamException(
			string name)
			: base(name)
        {
        }

		public CmsStreamException(
			string		name,
			Exception	e)
			: base(name, e)
        {
        }
    }
}
