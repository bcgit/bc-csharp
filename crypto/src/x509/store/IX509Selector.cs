using System;

namespace Org.BouncyCastle.X509.Store
{
	public interface IX509Selector
#if !PORTABLE
		: ICloneable
#endif
	{
#if PORTABLE
        object Clone();
#endif
        bool Match(object obj);
	}
}
