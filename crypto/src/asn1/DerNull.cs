using System;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A Null object.
	 */
	public class DerNull
		: Asn1Null
	{
		public static readonly DerNull Instance = new DerNull();

		private static readonly byte[] ZeroBytes = new byte[0];

		protected internal DerNull()
		{
		}

        internal override int EncodedLength(bool withID)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, 0);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
		{
            asn1Out.WriteEncodingDL(withID, Asn1Tags.Null, ZeroBytes);
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
		{
			return asn1Object is DerNull;
		}

		protected override int Asn1GetHashCode()
		{
			return -1;
		}
	}
}
