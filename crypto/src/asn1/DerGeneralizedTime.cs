using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerGeneralizedTime
        : Asn1GeneralizedTime
    {
        public DerGeneralizedTime(byte[] time)
            : base(time)
        {
        }

        public DerGeneralizedTime(DateTime time)
            : base(time)
        {
        }

        public DerGeneralizedTime(string time)
            : base(time)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime, GetDerTime());
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetDerTime());
        }
    }
}
