using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Class representing the DER-type External.</summary>
    public class DerExternal
        : Asn1Object
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerExternal), Asn1Tags.External) {}

            internal override Asn1Object FromImplicitConstructed(Asn1Sequence sequence)
            {
                return sequence.ToAsn1External();
            }
        }

        public static DerExternal FromSequence(Asn1Sequence seq)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DerExternal(seq);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static DerExternal FromVector(Asn1EncodableVector vector)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DerExternal(vector);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static DerExternal GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerExternal derExternal)
                return derExternal;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerExternal converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerExternal)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct external from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static DerExternal GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerExternal)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        public static DerExternal GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerExternal existing)
                return existing;

            return null;
        }

        public static DerExternal GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerExternal)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        internal readonly DerObjectIdentifier m_directReference;
        internal readonly DerInteger m_indirectReference;
        internal readonly Asn1ObjectDescriptor m_dataValueDescriptor;
        internal readonly int m_encoding;
        internal readonly Asn1Object m_externalContent;

        [Obsolete("Use 'FromVector' instead")]
        public DerExternal(Asn1EncodableVector vector)
            : this(new BerSequence(vector))
        {
        }

        [Obsolete("Use 'FromSequence' instead")]
        public DerExternal(Asn1Sequence sequence)
        {
            int offset = 0;

            Asn1Object asn1 = GetObjFromSequence(sequence, offset);
            if (asn1 is DerObjectIdentifier directReference)
            {
                m_directReference = directReference;
                asn1 = GetObjFromSequence(sequence, ++offset);
            }
            if (asn1 is DerInteger indirectReference)
            {
                m_indirectReference = indirectReference;
                asn1 = GetObjFromSequence(sequence, ++offset);
            }
            if (asn1 is Asn1ObjectDescriptor dataValueDescriptor)
            {
                m_dataValueDescriptor = dataValueDescriptor;
                asn1 = GetObjFromSequence(sequence, ++offset);
            }

            if (sequence.Count != offset + 1)
                throw new ArgumentException("input sequence too large", nameof(sequence));

            if (!(asn1 is Asn1TaggedObject externalData))
                throw new ArgumentException(
                    "No tagged object found in sequence. Structure doesn't seem to be of type External",
                        nameof(sequence));

            m_encoding = CheckEncoding(externalData.TagNo);
            m_externalContent = GetExternalContent(externalData);
        }

        /// <summary>Creates a new instance of DerExternal.</summary>
        /// <remarks>
        /// See X.690 for more information about the meaning of these parameters.
        /// </remarks>
        /// <param name="directReference">The direct reference or <c>null</c> if not set.</param>
        /// <param name="indirectReference">The indirect reference or <c>null</c> if not set.</param>
        /// <param name="dataValueDescriptor">The data value descriptor or <c>null</c> if not set.</param>
        /// <param name="externalData">The external data in its encoded form.</param>
        [Obsolete("Pass 'externalData' at type Asn1TaggedObject")]
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, DerTaggedObject externalData)
            : this(directReference, indirectReference, dataValueDescriptor, (Asn1TaggedObject)externalData)
        {
        }

        /// <summary>Creates a new instance of DerExternal.</summary>
        /// <remarks>
        /// See X.690 for more information about the meaning of these parameters.
        /// </remarks>
        /// <param name="directReference">The direct reference or <c>null</c> if not set.</param>
        /// <param name="indirectReference">The indirect reference or <c>null</c> if not set.</param>
        /// <param name="dataValueDescriptor">The data value descriptor or <c>null</c> if not set.</param>
        /// <param name="externalData">The external data in its encoded form.</param>
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, Asn1TaggedObject externalData)
        {
            m_directReference = directReference;
            m_indirectReference = indirectReference;
            m_dataValueDescriptor = dataValueDescriptor;
            m_encoding = CheckEncoding(externalData.TagNo);
            m_externalContent = GetExternalContent(externalData);
        }

        /// <summary>Creates a new instance of DerExternal.</summary>
        /// <remarks>
        /// See X.690 for more information about the meaning of these parameters.
        /// </remarks>
        /// <param name="directReference">The direct reference or <c>null</c> if not set.</param>
        /// <param name="indirectReference">The indirect reference or <c>null</c> if not set.</param>
        /// <param name="dataValueDescriptor">The data value descriptor or <c>null</c> if not set.</param>
        /// <param name="encoding">The encoding to be used for the external data.</param>
        /// <param name="externalData">The external data.</param>
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, int encoding, Asn1Object externalData)
        {
            m_directReference = directReference;
            m_indirectReference = indirectReference;
            m_dataValueDescriptor = dataValueDescriptor;
            m_encoding = CheckEncoding(encoding);
            m_externalContent = CheckExternalContent(encoding, externalData);
        }

        internal virtual Asn1Sequence BuildSequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.AddOptional(m_directReference, m_indirectReference, m_dataValueDescriptor);
            v.Add(new DerTaggedObject(isExplicit: 0 == m_encoding, m_encoding, m_externalContent));
            return new DerSequence(v);
        }

        internal sealed override IAsn1Encoding GetEncoding(int encoding) =>
            GetEncodingImplicit(encoding, Asn1Tags.Universal, Asn1Tags.External);

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            BuildSequence().GetEncodingImplicit(Asn1OutputStream.EncodingDer, tagClass, tagNo);

        internal sealed override DerEncoding GetEncodingDer() =>
            GetEncodingDerImplicit(Asn1Tags.Universal, Asn1Tags.External);

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            BuildSequence().GetEncodingDerImplicit(tagClass, tagNo);

        protected override int Asn1GetHashCode()
        {
            return Objects.GetHashCode(m_directReference)
                ^  Objects.GetHashCode(m_indirectReference)
                ^  Objects.GetHashCode(m_dataValueDescriptor)
                ^  m_encoding
                ^  m_externalContent.GetHashCode();
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return asn1Object is DerExternal that
                && Equals(this.m_directReference, that.m_directReference)
                && Equals(this.m_indirectReference, that.m_indirectReference)
                && Equals(this.m_dataValueDescriptor, that.m_dataValueDescriptor)
                && this.m_encoding == that.m_encoding
                && this.m_externalContent.Equals(that.m_externalContent);
        }

        public Asn1ObjectDescriptor DataValueDescriptor => m_dataValueDescriptor;

        public DerObjectIdentifier DirectReference => m_directReference;

        /// <summary>The encoding of the content.</summary>
        /// <remarks>
        /// Valid values are:
        /// <list>
        /// <item><c>0</c>: single-ASN1-type</item>
        /// <item><c>1</c>: OCTET STRING</item>
        /// <item><c>2</c>: BIT STRING</item>
        /// </list>
        /// </remarks>
        public int Encoding => m_encoding;

        public Asn1Object ExternalContent => m_externalContent;

        public DerInteger IndirectReference => m_indirectReference;

        private static int CheckEncoding(int encoding)
        {
            if (encoding < 0 || encoding > 2)
                throw new InvalidOperationException("invalid encoding value: " + encoding);

            return encoding;
        }

        private static Asn1Object CheckExternalContent(int tagNo, Asn1Object externalContent)
        {
            switch (tagNo)
            {
            case 1:
                return Asn1OctetString.Meta.Instance.CheckedCast(externalContent);
            case 2:
                return DerBitString.Meta.Instance.CheckedCast(externalContent);
            default:
                return externalContent;
            }
        }

        private static Asn1Object GetExternalContent(Asn1TaggedObject externalData)
        {
            Asn1Utilities.CheckContextTagClass(externalData);

            switch (externalData.TagNo)
            {
            case 0:
                return externalData.GetExplicitBaseObject().ToAsn1Object();
            case 1:
                return Asn1OctetString.GetTagged(externalData, false);
            case 2:
                return DerBitString.GetTagged(externalData, false);
            default:
                throw new ArgumentException("unknown tag: " + Asn1Utilities.GetTagText(externalData),
                    nameof(externalData));
            }
        }

        private static Asn1Object GetObjFromSequence(Asn1Sequence sequence, int index)
        {
            if (sequence.Count <= index)
                throw new ArgumentException("too few objects in input sequence", nameof(sequence));

            return sequence[index].ToAsn1Object();
        }
    }
}
