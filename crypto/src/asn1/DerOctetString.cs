using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerOctetString
        : Asn1OctetString
    {
		/// <param name="contents">The octets making up the octet string.</param>
        public DerOctetString(byte[] contents)
			: base(contents)
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

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.OctetString, contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, contents);
        }

        internal static void Encode(Asn1OutputStream asn1Out, byte[] buf, int off, int len)
		{
            asn1Out.WriteIdentifier(Asn1Tags.Universal, Asn1Tags.OctetString);
            asn1Out.WriteDL(len);
            asn1Out.Write(buf, off, len);
        }
    }
}
