using System;

namespace Org.BouncyCastle.Asn1
{
    public class DLExternal
        : DerExternal
    {
        public static new DLExternal FromSequence(Asn1Sequence seq)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DLExternal(seq);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static new DLExternal FromVector(Asn1EncodableVector vector)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DLExternal(vector);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        [Obsolete("Use 'FromVector' instead")]
        public DLExternal(Asn1EncodableVector vector)
            : base(vector)
        {
        }

        [Obsolete("Use 'FromSequence' instead")]
        public DLExternal(Asn1Sequence sequence)
            : base(sequence)
        {
        }

        /// <summary>Creates a new instance of DLExternal.</summary>
        /// <remarks>
        /// See X.690 for more information about the meaning of these parameters.
        /// </remarks>
        /// <param name="directReference">The direct reference or <c>null</c> if not set.</param>
        /// <param name="indirectReference">The indirect reference or <c>null</c> if not set.</param>
        /// <param name="dataValueDescriptor">The data value descriptor or <c>null</c> if not set.</param>
        /// <param name="externalData">The external data in its encoded form.</param>
        public DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, Asn1TaggedObject externalData)
            : base(directReference, indirectReference, dataValueDescriptor, externalData)
        {
        }

        /// <summary>Creates a new instance of DLExternal.</summary>
        /// <remarks>
        /// See X.690 for more information about the meaning of these parameters.
        /// </remarks>
        /// <param name="directReference">The direct reference or <c>null</c> if not set.</param>
        /// <param name="indirectReference">The indirect reference or <c>null</c> if not set.</param>
        /// <param name="dataValueDescriptor">The data value descriptor or <c>null</c> if not set.</param>
        /// <param name="encoding">The encoding to be used for the external data.</param>
        /// <param name="externalData">The external data.</param>
        public DLExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, int encoding, Asn1Object externalData)
            : base(directReference, indirectReference, dataValueDescriptor, encoding, externalData)
        {
        }

        internal override Asn1Sequence BuildSequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.AddOptional(m_directReference, m_indirectReference, m_dataValueDescriptor);
            v.Add(new DLTaggedObject(isExplicit: 0 == m_encoding, m_encoding, m_externalContent));
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
