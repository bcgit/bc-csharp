using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ANS.1 def for Diffie-Hellman key exchange OtherInfo structure. See
     * RFC 2631, or X9.42, for further details.
     */
    public class OtherInfo
        : Asn1Encodable
    {
        public static OtherInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherInfo otherInfo)
                return otherInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OtherInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static OtherInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OtherInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly KeySpecificInfo m_keyInfo;
        private readonly Asn1OctetString m_partyAInfo;
        private readonly Asn1OctetString m_suppPubInfo;

        [Obsolete("Use 'GetInstance' instead")]
        public OtherInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyInfo = KeySpecificInfo.GetInstance(seq[pos++]);
            m_partyAInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);
            m_suppPubInfo = Asn1Utilities.ReadContextTagged(seq, ref pos, 2, true, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public OtherInfo(KeySpecificInfo keyInfo, Asn1OctetString partyAInfo, Asn1OctetString suppPubInfo)
        {
            m_keyInfo = keyInfo ?? throw new ArgumentNullException(nameof(keyInfo));
            m_partyAInfo = partyAInfo;
            m_suppPubInfo = suppPubInfo ?? throw new ArgumentNullException(nameof(suppPubInfo));
        }

        public KeySpecificInfo KeyInfo => m_keyInfo;

        public Asn1OctetString PartyAInfo => m_partyAInfo;

        public Asn1OctetString SuppPubInfo => m_suppPubInfo;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  OtherInfo ::= Sequence {
         *      keyInfo KeySpecificInfo,
         *      partyAInfo [0] OCTET STRING OPTIONAL,
         *      suppPubInfo [2] OCTET STRING
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_keyInfo);
            v.AddOptionalTagged(true, 0, m_partyAInfo);
            v.Add(new DerTaggedObject(2, m_suppPubInfo));
            return new DerSequence(v);
        }
    }
}
