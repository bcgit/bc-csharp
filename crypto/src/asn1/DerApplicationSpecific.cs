using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Base class for an application specific object
     */
    public class DerApplicationSpecific
        : Asn1Object
    {
        public static DerApplicationSpecific GetInstance(object obj)
        {
            if (obj == null || obj is DerApplicationSpecific)
            {
                return (DerApplicationSpecific)obj;
            }
            else if (obj is byte[])
            {
                try
                {
                    return GetInstance(FromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct application-specific from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        internal readonly Asn1TaggedObject m_taggedObject;

        /**
         * Create an application specific object from the passed in data. This will assume
         * the data does not represent a constructed object.
         *
         * @param tagNo the tag number for this object.
         * @param contentsOctets the encoding of the object's body.
         */
        public DerApplicationSpecific(int tagNo, byte[] contentsOctets)
            : this(new DerTaggedObject(false, Asn1Tags.Application, tagNo, new DerOctetString(contentsOctets)))
        {
        }

        /**
         * Create an application specific object with a tagging of explicit/constructed.
         *
         * @param tag the tag number for this object.
         * @param object the object to be contained.
         */
        public DerApplicationSpecific(int tag, Asn1Encodable baseEncodable)
            : this(true, tag, baseEncodable)
        {
        }

        /**
         * Create an application specific object with the tagging style given by the value of explicit.
         *
         * @param explicit true if the object is explicitly tagged.
         * @param tagNo the tag number for this object.
         * @param baseEncodable the object to be contained.
         */
        public DerApplicationSpecific(bool isExplicit, int tagNo, Asn1Encodable baseEncodable)
            : this(new DerTaggedObject(isExplicit, Asn1Tags.Application, tagNo, baseEncodable))
        {
        }

        /**
         * Create an application specific object which is marked as constructed
         *
         * @param tagNo the tag number for this object.
         * @param contentsElements   the objects making up the application specific object.
         */
        public DerApplicationSpecific(int tagNo, Asn1EncodableVector contentsElements)
            : this(new DerTaggedObject(false, Asn1Tags.Application, tagNo, DerSequence.FromVector(contentsElements)))
        {
        }

        internal DerApplicationSpecific(Asn1TaggedObject taggedObject)
            //: base(taggedObject.explicitness, CheckTagClass(taggedObject.tagClass), taggedObject.tagNo,
            //      taggedObject.obj)
        {
            CheckTagClass(taggedObject.TagClass);

            this.m_taggedObject = taggedObject;
        }

        public int ApplicationTag
        {
            get { return m_taggedObject.TagNo; }
        }

        public byte[] GetContents()
        {
            return m_taggedObject.GetContents();
        }

        public Asn1Object GetEnclosedObject()
        {
            return m_taggedObject.GetBaseObject().ToAsn1Object();
        }

        [Obsolete("Use GetEnclosedObject instead")]
        public Asn1Object GetObject()
        {
            return GetEnclosedObject();
        }

        public Asn1Object GetObject(int tagNo)
        {
            // TODO[asn1] Implement Asn1TaggedObject.GetBaseUniversal
            //return taggedObject.GetBaseUniversal(false, tagNo);

            if (tagNo >= 0x1F)
                throw new IOException("unsupported tag number");

            byte[] orig = this.GetEncoded();
            byte[] tmp = ReplaceTagNumber(tagNo, orig);

            if ((orig[0] & Asn1Tags.Constructed) != 0)
            {
                tmp[0] |= Asn1Tags.Constructed;
            }

            return FromByteArray(tmp);
        }

        public bool HasApplicationTag(int tagNo)
        {
            return m_taggedObject.HasTag(Asn1Tags.Application, tagNo);
        }

        [Obsolete("Will be removed")]
        public bool IsConstructed()
        {
            return m_taggedObject.IsConstructed();
        }

        /**
         * DerApplicationSpecific uses an internal Asn1TaggedObject for the
         * implementation, and will soon be deprecated in favour of using
         * Asn1TaggedObject with a tag class of {@link Asn1Tags#Application}. This method
         * lets you get the internal Asn1TaggedObject so that client code can begin the
         * migration.
         */
        public Asn1TaggedObject TaggedObject
        {
            get { return m_taggedObject; }
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            Asn1TaggedObject that;
            if (asn1Object is DerApplicationSpecific)
            {
                that = ((DerApplicationSpecific)asn1Object).m_taggedObject;
            }
            else if (asn1Object is Asn1TaggedObject)
            {
                that = (Asn1TaggedObject)asn1Object;
            }
            else
            {
                return false;
            }

            return m_taggedObject.Equals(that);
        }

        protected override int Asn1GetHashCode()
        {
            return m_taggedObject.CallAsn1GetHashCode();
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return m_taggedObject.GetEncoding(encoding);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return m_taggedObject.GetEncodingImplicit(encoding, tagClass, tagNo);
        }

        private byte[] ReplaceTagNumber(int newTag, byte[] input)
        {
            int tagNo = input[0] & 0x1f;
            int index = 1;

            // with tagged object tag number is bottom 5 bits, or stored at the start of the content
            if (tagNo == 0x1f)
            {
                int b = input[index++];

                // X.690-0207 8.1.2.4.2
                // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
                if ((b & 0x7f) == 0) // Note: -1 will pass
                    throw new IOException("corrupted stream - invalid high tag number found");

                while ((b & 0x80) != 0)
                {
                    b = input[index++];
                }
            }

            int remaining = input.Length - index;
            byte[] tmp = new byte[1 + remaining];
            tmp[0] = (byte)newTag;
            Array.Copy(input, index, tmp, 1, remaining);
            return tmp;
        }

        private static int CheckTagClass(int tagClass)
        {
            if (Asn1Tags.Application != tagClass)
                throw new ArgumentException();

            return tagClass;
        }
    }
}
