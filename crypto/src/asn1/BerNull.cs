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

		internal override void Encode(DerOutputStream derOut)
		{
            if (derOut.IsBer)
			{
				derOut.WriteByte(Asn1Tags.Null);
			}
			else
			{
				base.Encode(derOut);
			}
		}
	}
}
