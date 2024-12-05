using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    // TODO[api] Should only be Asn1Encodable
    public class CmcePublicKey
        : Asn1Object
    {
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

        public static CmcePublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CmcePublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

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

        public static CmcePublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CmcePublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_t;

        public CmcePublicKey(byte[] t)
        {
            m_t = DerOctetString.FromContents(t);
        }

        [Obsolete("Use 'GetInstance' instead")]
        public CmcePublicKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_t = Asn1OctetString.GetInstance(seq[0]);
        }

        public byte[] T => Arrays.Clone(m_t.GetOctets());

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

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToAsn1Primitive().CallAsn1Equals(asn1Object);
        }

        protected override int Asn1GetHashCode()
        {
            return ToAsn1Primitive().CallAsn1GetHashCode();
        }
    }
}
