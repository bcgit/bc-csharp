using System;

namespace Org.BouncyCastle.Cms
{
		public class CmsException
			: Exception
		{
		public CmsException()
		{
		}

		public CmsException(
			string msg)
			: base(msg)
		{
		}

		public CmsException(
			string		msg,
			Exception	e)
			: base(msg, e)
		{
		}
	}
}
