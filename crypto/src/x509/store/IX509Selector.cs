using System;

namespace Org.BouncyCastle.X509.Store
{
	public interface IX509Selector
#if !(SILVERLIGHT || UNITY_WINRT)
		: ICloneable
#endif
	{
#if SILVERLIGHT || UNITY_WINRT
        object Clone();
#endif
        bool Match(object obj);
	}
}
