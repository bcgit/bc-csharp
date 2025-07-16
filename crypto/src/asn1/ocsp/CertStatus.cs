using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class CertStatus
        : Asn1Encodable, IAsn1Choice
    {
        public static CertStatus GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static CertStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static CertStatus GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertStatus certStatus)
                return certStatus;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new CertStatus(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static CertStatus GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case 0:
                    return Asn1Null.GetTagged(taggedObject, false);
                case 1:
                    return RevokedInfo.GetTagged(taggedObject, false);
                case 2:
                    return Asn1Null.GetTagged(taggedObject, false);
                }
            }

            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_value;

        /**
         * create a CertStatus object with a tag of zero.
         */
        public CertStatus()
        {
            m_tagNo = 0;
            m_value = DerNull.Instance;
        }

        public CertStatus(RevokedInfo info)
        {
            m_tagNo = 1;
            m_value = info ?? throw new ArgumentNullException(nameof(info));
        }

        public CertStatus(int tagNo, Asn1Encodable value)
        {
            m_tagNo = tagNo;
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public CertStatus(Asn1TaggedObject choice)
        {
            m_tagNo = choice.TagNo;
            m_value = GetOptionalBaseObject(choice) ??
                throw new ArgumentException("unknown tag: " + Asn1Utilities.GetTagText(choice), nameof(choice));
        }

        public int TagNo => m_tagNo;

        public Asn1Encodable Status => m_value;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  CertStatus ::= CHOICE {
         *                  good        [0]     IMPLICIT Null,
         *                  revoked     [1]     IMPLICIT RevokedInfo,
         *                  unknown     [2]     IMPLICIT UnknownInfo }
         *
         * UnknownInfo ::= NULL
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerTaggedObject(false, m_tagNo, m_value);
    }
}
