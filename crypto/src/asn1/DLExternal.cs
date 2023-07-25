namespace Org.BouncyCastle.Asn1
{
    public class DLExternal
        : DerExternal
    {
        public DLExternal(Asn1EncodableVector vector)
            : base(vector)
        {
        }

        public DLExternal(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        public DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, Asn1TaggedObject externalData)
            : base(directReference, indirectReference, dataValueDescriptor, externalData)
        {
        }

        public DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
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

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return BuildSequence().GetEncodingImplicit(Asn1OutputStream.EncodingDL, tagClass, tagNo);
        }
    }
}
