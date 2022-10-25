using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerUtcTime
        : Asn1UtcTime
    {
        public DerUtcTime(string time)
			: base(time)
        {
        }

        public DerUtcTime(DateTime time)
			: base(time)
        {
        }

		internal DerUtcTime(byte[] contents)
			: base(contents)
        {
        }

        // TODO: create proper DER encoding.
    }
}
