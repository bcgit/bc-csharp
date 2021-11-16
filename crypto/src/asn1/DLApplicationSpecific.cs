using System;

namespace Org.BouncyCastle.Asn1
{
    internal class DLApplicationSpecific
        : DerApplicationSpecific
    {
        internal DLApplicationSpecific(int tagNo, Asn1Encodable baseEncodable)
            : this(true, tagNo, baseEncodable)
        {
        }

        internal DLApplicationSpecific(bool isExplicit, int tagNo, Asn1Encodable baseEncodable)
            : base(new DLTaggedObject(isExplicit, Asn1Tags.Application, tagNo, baseEncodable))
        {
        }

        internal DLApplicationSpecific(int tagNo, Asn1EncodableVector contentsElements)
            : base(new DLTaggedObject(false, Asn1Tags.Application, tagNo, DLSequence.FromVector(contentsElements)))
        {
        }

        internal DLApplicationSpecific(Asn1TaggedObject taggedObject)
            : base(taggedObject)
        {
        }
    }
}
