using System;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A BER Null object.
	 */
	public class BerNull
		: DerNull
	{
		public static new readonly BerNull Instance = new BerNull();

		private BerNull()
            : base()
		{
		}

		internal override void Encode(Asn1OutputStream asn1Out)
		{
            if (asn1Out.IsBer)
			{
				asn1Out.WriteByte(Asn1Tags.Null);
			}
			else
			{
				base.Encode(asn1Out);
			}
		}
	}
}
