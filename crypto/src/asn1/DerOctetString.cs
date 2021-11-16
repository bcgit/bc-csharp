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

        internal override bool EncodeConstructed(int encoding)
        {
            return false;
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, contents.Length);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out.WriteEncodingDL(withID, Asn1Tags.OctetString, contents);
        }

        internal static void Encode(Asn1OutputStream asn1Out, bool withID, byte[] buf, int off, int len)
		{
			asn1Out.WriteEncodingDL(withID, Asn1Tags.OctetString, buf, off, len);
		}

        internal static int EncodedLength(bool withID, int contentsLength)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, contentsLength);
        }
    }
}
