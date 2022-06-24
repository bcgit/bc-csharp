using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.X509.Store
{
    [Serializable]
    public class X509StoreException
		: Exception
	{
		public X509StoreException()
			: base()
		{
		}

		public X509StoreException(string message)
			: base(message)
		{
		}

		public X509StoreException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected X509StoreException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
