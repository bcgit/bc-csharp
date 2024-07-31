using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
     * RFC 2631, or X9.42, for further details.
     */
    public class KeySpecificInfo
        : Asn1Encodable
    {
        public static KeySpecificInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KeySpecificInfo keySpecificInfo)
                return keySpecificInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KeySpecificInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KeySpecificInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_algorithm;
        private readonly Asn1OctetString m_counter;

        [Obsolete("Use 'GetInstance' instead")]
        public KeySpecificInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = DerObjectIdentifier.GetInstance(seq[0]);
            m_counter = Asn1OctetString.GetInstance(seq[1]);
        }

        public KeySpecificInfo(DerObjectIdentifier algorithm, Asn1OctetString counter)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_counter = counter ?? throw new ArgumentNullException(nameof(counter));
        }

        public DerObjectIdentifier Algorithm => m_algorithm;

        public Asn1OctetString Counter => m_counter;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  KeySpecificInfo ::= Sequence {
         *      algorithm OBJECT IDENTIFIER,
         *      counter OCTET STRING SIZE (4..4)
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algorithm, m_counter);
    }
}
