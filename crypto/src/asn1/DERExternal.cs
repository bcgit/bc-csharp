using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
	/**
	* Class representing the DER-type External
	*/
	public class DerExternal
		: Asn1Object
	{
        public static DerExternal GetInstance(object obj)
        {
            if (obj == null || obj is DerExternal)
            {
                return (DerExternal)obj;
            }
            if (obj is Asn1Encodable)
            {
                Asn1Object asn1 = ((Asn1Encodable)obj).ToAsn1Object();
                if (asn1 is DerExternal)
                    return (DerExternal)asn1;
            }
            if (obj is byte[])
            {
                try
                {
                    return GetInstance(FromByteArray((byte[])obj));
                }
                catch (Exception e)
                {
                    throw new ArgumentException("encoding error in GetInstance: " + e.ToString(), "obj");
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        public static DerExternal GetInstance(Asn1TaggedObject taggedObject, bool isExplicit)
        {
            Asn1Object baseObject = taggedObject.GetObject();

            if (isExplicit || baseObject is DerExternal)
            {
                return GetInstance(baseObject);
            }

            return Asn1Sequence.GetInstance(taggedObject, false).ToAsn1External();
        }

		private readonly DerObjectIdentifier directReference;
		private readonly DerInteger indirectReference;
        private readonly Asn1ObjectDescriptor dataValueDescriptor;
		private readonly int encoding;
		private readonly Asn1Object externalContent;

        [Obsolete("Use constructor taking an Asn1Sequence instead.")]
        public DerExternal(Asn1EncodableVector vector)
            : this(new DerSequence(vector))
        {
        }

        public DerExternal(DerSequence sequence)
		{
			int offset = 0;

			Asn1Object asn1 = GetObjFromSequence(sequence, offset);
			if (asn1 is DerObjectIdentifier)
			{
				directReference = (DerObjectIdentifier)asn1;
                asn1 = GetObjFromSequence(sequence, ++offset);
			}
			if (asn1 is DerInteger)
			{
				indirectReference = (DerInteger)asn1;
                asn1 = GetObjFromSequence(sequence, ++offset);
			}
			if (!(asn1 is Asn1TaggedObject))
			{
				dataValueDescriptor = (Asn1ObjectDescriptor)asn1;
                asn1 = GetObjFromSequence(sequence, ++offset);
			}

            if (sequence.Count != offset + 1)
				throw new ArgumentException("input sequence too large", "sequence");

            if (!(asn1 is Asn1TaggedObject))
				throw new ArgumentException(
                    "No tagged object found in sequence. Structure doesn't seem to be of type External", "sequence");

            Asn1TaggedObject obj = (Asn1TaggedObject)asn1;
			this.encoding = CheckEncoding(obj.TagNo);
            this.externalContent = GetExternalContent(obj);
		}

        [Obsolete("Use constructor with dataValueDescriptor of type Asn1ObjectDescriptor")]
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1Object dataValueDescriptor, DerTaggedObject externalData)
			: this(directReference, indirectReference, CheckDataValueDescriptor(dataValueDescriptor), externalData)
		{
		}

        /**
		* Creates a new instance of DerExternal
		* See X.690 for more informations about the meaning of these parameters
		* @param directReference The direct reference or <code>null</code> if not set.
		* @param indirectReference The indirect reference or <code>null</code> if not set.
		* @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
		* @param externalData The external data in its encoded form.
		*/
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, DerTaggedObject externalData)
        {
            this.directReference = directReference;
            this.indirectReference = indirectReference;
            this.dataValueDescriptor = dataValueDescriptor;
            this.encoding = CheckEncoding(externalData.TagNo);
            this.externalContent = GetExternalContent(externalData);
        }

        [Obsolete("Use constructor with dataValueDescriptor of type Asn1ObjectDescriptor")]
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1Object dataValueDescriptor, int encoding, Asn1Object externalData)
            : this(directReference, indirectReference, CheckDataValueDescriptor(dataValueDescriptor), encoding,
                  externalData)
		{
		}

        /**
		* Creates a new instance of DerExternal.
		* See X.690 for more informations about the meaning of these parameters
		* @param directReference The direct reference or <code>null</code> if not set.
		* @param indirectReference The indirect reference or <code>null</code> if not set.
		* @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
		* @param encoding The encoding to be used for the external data
		* @param externalData The external data
		*/
        public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
            Asn1ObjectDescriptor dataValueDescriptor, int encoding, Asn1Object externalData)
        {
            this.directReference = directReference;
            this.indirectReference = indirectReference;
            this.dataValueDescriptor = dataValueDescriptor;
            this.encoding = CheckEncoding(encoding);
            this.externalContent = CheckExternalContent(encoding, externalData);
        }

        internal Asn1Sequence BuildSequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.AddOptional(directReference, indirectReference, dataValueDescriptor);
            v.Add(new DerTaggedObject(0 == encoding, encoding, externalContent));
            return new DerSequence(v);
        }

        internal override bool EncodeConstructed()
        {
            //return BuildSequence().EncodeConstructed();
            return true;
        }

        internal override int EncodedLength(bool withID)
        {
            return BuildSequence().EncodedLength(withID);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.External);
            BuildSequence().Encode(asn1Out, false);
        }

        protected override int Asn1GetHashCode()
		{
            return Platform.GetHashCode(this.directReference)
                ^  Platform.GetHashCode(this.indirectReference)
                ^  Platform.GetHashCode(this.dataValueDescriptor)
                ^  this.encoding
                ^  this.externalContent.GetHashCode();
		}

		protected override bool Asn1Equals(Asn1Object asn1Object)
		{
			DerExternal that = asn1Object as DerExternal;
            return null != that
                && Platform.Equals(this.directReference, that.directReference)
                && Platform.Equals(this.indirectReference, that.indirectReference)
                && Platform.Equals(this.dataValueDescriptor, that.dataValueDescriptor)
                && this.encoding == that.encoding
				&& this.externalContent.Equals(that.externalContent);
		}

		public Asn1ObjectDescriptor DataValueDescriptor
		{
			get { return dataValueDescriptor; }
		}

		public DerObjectIdentifier DirectReference
		{
			get { return directReference; }
		}

		/**
		* The encoding of the content. Valid values are
		* <ul>
		* <li><code>0</code> single-ASN1-type</li>
		* <li><code>1</code> OCTET STRING</li>
		* <li><code>2</code> BIT STRING</li>
		* </ul>
		*/
		public int Encoding
		{
            get { return encoding; }
		}

		public Asn1Object ExternalContent
		{
			get { return externalContent; }
		}

		public DerInteger IndirectReference
		{
			get { return indirectReference; }
		}

        private static Asn1ObjectDescriptor CheckDataValueDescriptor(Asn1Object dataValueDescriptor)
        {
            if (dataValueDescriptor is Asn1ObjectDescriptor)
                return (Asn1ObjectDescriptor)dataValueDescriptor;
            if (dataValueDescriptor is DerGraphicString)
                return new Asn1ObjectDescriptor((DerGraphicString)dataValueDescriptor);

            throw new ArgumentException("incompatible type for data-value-descriptor", "dataValueDescriptor");
        }

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
                //return ASN1OctetString.TYPE.checkedCast(externalContent);
                return (Asn1OctetString)externalContent;
            case 2:
                //return ASN1BitString.TYPE.checkedCast(externalContent);
                return (DerBitString)externalContent;
            default:
                return externalContent;
            }
        }

        private static Asn1Object GetExternalContent(Asn1TaggedObject encoding)
        {
            int tagClass = encoding.TagClass, tagNo = encoding.TagNo;
            if (Asn1Tags.ContextSpecific != tagClass)
                throw new ArgumentException("invalid tag: " + Asn1Utilities.GetTagText(tagClass, tagNo), "encoding");

            switch (tagNo)
            {
            case 0:
                return encoding.GetExplicitBaseObject().ToAsn1Object();
            case 1:
                return Asn1OctetString.GetInstance(encoding, false);
            case 2:
                return DerBitString.GetInstance(encoding, false);
            default:
                throw new ArgumentException("invalid tag: " + Asn1Utilities.GetTagText(tagClass, tagNo), "encoding");
            }
        }

        private static Asn1Object GetObjFromSequence(Asn1Sequence sequence, int index)
		{
			if (sequence.Count <= index)
				throw new ArgumentException("too few objects in input sequence", "sequence");

			return sequence[index].ToAsn1Object();
		}
	}
}
