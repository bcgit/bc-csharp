using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /// <summary>The ASN.1 structure of a Classic McEliece public key.</summary>
    // TODO[api] Should only be Asn1Encodable
    public class CmcePublicKey
        : Asn1Object
    {
        /// <summary>Return an <see cref="CmcePublicKey"/> from a tagged object.</summary>
        /// <param name="o">The object.</param>
        /// <returns>The <see cref="CmcePublicKey"/>.</returns>
        public static CmcePublicKey GetInstance(Object o)
        {
            if (o == null)
                return null;
            if (o is CmcePublicKey cmcePublicKey)
                return cmcePublicKey;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CmcePublicKey(Asn1Sequence.GetInstance(o));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CmcePublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CmcePublicKey"/>.</returns>
        public static CmcePublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CmcePublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CmcePublicKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CmcePublicKey"/>, or null if <paramref name="element"/> is null.</returns>
        public static CmcePublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CmcePublicKey cmcePublicKey)
                return cmcePublicKey;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
#pragma warning disable CS0618 // Type or member is obsolete
                return new CmcePublicKey(asn1Sequence);
#pragma warning restore CS0618 // Type or member is obsolete

            return null;
        }

        /// <summary>Return an <see cref="CmcePublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CmcePublicKey"/>.</returns>
        public static CmcePublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CmcePublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_t;

        /// <summary>Create a new <see cref="CmcePublicKey"/>.</summary>
        /// <param name="t">The t.</param>
        public CmcePublicKey(byte[] t)
        {
            m_t = DerOctetString.FromContents(t);
        }

        /// <summary>Create a new <see cref="CmcePublicKey"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public CmcePublicKey(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_t = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the t.</summary>
        public byte[] T => Arrays.Clone(m_t.GetOctets());

        /// <summary>Convert this object to an ASN.1 primitive.</summary>
        /// <returns>The ASN.1 object.</returns>
        public Asn1Object ToAsn1Primitive() => new DerSequence(m_t);

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToAsn1Primitive().GetEncoding(encoding);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo);
        }

        internal override DerEncoding GetEncodingDer()
        {
            return ToAsn1Primitive().GetEncodingDer();
        }

        internal override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingDerImplicit(tagClass, tagNo);
        }

        /// <inheritdoc/>
        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToAsn1Primitive().CallAsn1Equals(asn1Object);
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode()
        {
            return ToAsn1Primitive().CallAsn1GetHashCode();
        }
    }
}
