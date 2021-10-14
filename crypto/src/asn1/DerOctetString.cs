using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerOctetString
        : Asn1OctetString
    {
		/// <param name="str">The octets making up the octet string.</param>
        public DerOctetString(
			byte[] str)
			: base(str)
        {
        }

        public DerOctetString(IAsn1Convertible obj)
            : this(obj.ToAsn1Object())
        {
        }

        public DerOctetString(Asn1Encodable obj)
            : base(obj.GetEncoded(Der))
        {
        }

        internal override void Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteEncoded(Asn1Tags.OctetString, str);
        }

		internal static void Encode(Asn1OutputStream asn1Out, byte[] bytes, int offset, int length)
		{
			asn1Out.WriteEncoded(Asn1Tags.OctetString, bytes, offset, length);
		}
	}
}
