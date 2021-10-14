using System;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A BER Null object.
	 */
    [Obsolete("Use 'DerNull' instead")]
	public class BerNull
		: DerNull
	{
        [Obsolete("Use 'DerNull.Instance' instead")]
        public static new readonly BerNull Instance = new BerNull();

		private BerNull()
            : base()
		{
		}
	}
}
