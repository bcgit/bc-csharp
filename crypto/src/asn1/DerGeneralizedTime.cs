using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 GeneralizedTime with DER encoding.</summary>
    public class DerGeneralizedTime
        : Asn1GeneralizedTime
    {
        /// <summary>Create a new <see cref="DerGeneralizedTime"/>.</summary>
        /// <param name="timeString">The time string.</param>
        public DerGeneralizedTime(string timeString)
            : base(timeString)
        {
        }

        /// <summary>Create a new <see cref="DerGeneralizedTime"/>.</summary>
        /// <param name="dateTime">The date time.</param>
        public DerGeneralizedTime(DateTime dateTime)
            : base(dateTime)
        {
        }

        internal DerGeneralizedTime(byte[] contents)
            : base(contents)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime,
                GetContents(Asn1OutputStream.EncodingDer));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));
        }
    }
}
