using System;

namespace Org.BouncyCastle.Asn1
{
	public class Asn1ParsingException
		: InvalidOperationException
	{
		public Asn1ParsingException()
			: base()
		{
		}

		public Asn1ParsingException(
			string message)
			: base(message)
		{
		}

		public Asn1ParsingException(
			string		message,
			Exception	exception)
			: base(message, exception)
		{
		}
	}
}
