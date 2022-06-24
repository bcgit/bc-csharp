using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.X509.Store
{
    [Serializable]
    public class NoSuchStoreException
		: X509StoreException
	{
		public NoSuchStoreException()
			: base()
		{
		}

		public NoSuchStoreException(string message)
			: base(message)
		{
		}

		public NoSuchStoreException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected NoSuchStoreException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
