namespace Org.BouncyCastle.Asn1
{
    internal class DLExternal
        : DerExternal
    {
        internal DLExternal(Asn1EncodableVector vector)
            : base(vector)
        {
        }

        internal DLExternal(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        internal DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, Asn1TaggedObject externalData)
            : base(directReference, indirectReference, dataValueDescriptor, externalData)
        {
        }

        internal DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, int encoding, Asn1Object externalData)
            : base(directReference, indirectReference, dataValueDescriptor, encoding, externalData)
        {
        }

        internal override Asn1Sequence BuildSequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.AddOptional(directReference, indirectReference, dataValueDescriptor);
            v.Add(new DLTaggedObject(0 == encoding, encoding, externalContent));
            return new DLSequence(v);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            return BuildSequence().GetEncodingImplicit(encoding, Asn1Tags.Universal, Asn1Tags.External);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return BuildSequence().GetEncodingImplicit(encoding, tagClass, tagNo);
        }
    }
}
