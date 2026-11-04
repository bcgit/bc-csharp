using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Der T61String (also the teletex string) - 8-bit characters
     */
    public class DerT61String
        : DerStringBase
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerT61String), Asn1Tags.T61String) {}

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }
        }

        /**
         * return a T61 string from the passed in object.
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerT61String GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is DerT61String derT61String)
                return derT61String;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerT61String converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (DerT61String)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct T61 string from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /**
         * return a T61 string from a tagged object.
         *
         * @param taggedObject the tagged object holding the object we want
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static DerT61String GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerT61String)Meta.Instance.GetContextTagged(taggedObject, declaredExplicit);
        }

        /// <summary>Return an <see cref="DerT61String"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="DerT61String"/>, or null if <paramref name="element"/> is null.</returns>
        public static DerT61String GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerT61String existing)
                return existing;

            return null;
        }

        /// <summary>Return an <see cref="DerT61String"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DerT61String"/>.</returns>
        public static DerT61String GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerT61String)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        private readonly byte[] m_contents;

        /// <summary>Create a new <see cref="DerT61String"/>.</summary>
        /// <param name="str">The str.</param>
        public DerT61String(string str)
        {
            if (str == null)
                throw new ArgumentNullException("str");

            m_contents = Strings.ToByteArray(str);
        }

        /// <summary>Create a new <see cref="DerT61String"/>.</summary>
        /// <param name="contents">The contents.</param>
        public DerT61String(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerT61String(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException(nameof(contents));

            m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        /// <inheritdoc/>
        public override string GetString()
        {
            return Strings.FromByteArray(m_contents);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.T61String, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.T61String, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        /// <summary>Return the octets.</summary>
        public byte[] GetOctets()
        {
            return Arrays.Clone(m_contents);
        }

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerT61String that = asn1Object as DerT61String;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode()
        {
            return Arrays.GetHashCode(m_contents);
        }

        internal static DerT61String CreatePrimitive(byte[] contents)
        {
            return new DerT61String(contents, false);
        }
    }
}
