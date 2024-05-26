using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class CertStatus
        : Asn1Encodable, IAsn1Choice
    {
        public static CertStatus GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertStatus certStatus)
                return certStatus;
            return new CertStatus(Asn1TaggedObject.GetInstance(obj));
        }

        public static CertStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        private static Asn1Encodable GetValue(Asn1TaggedObject choice)
        {
            if (choice.HasContextTag())
            {
                switch (choice.TagNo)
                {
                case 0:
                    return Asn1Null.GetInstance(choice, false);
                case 1:
                    return RevokedInfo.GetInstance(choice, false);
                case 2:
                    return Asn1Null.GetInstance(choice, false);
                }
            }

            throw new ArgumentException("unknown tag: " + Asn1Utilities.GetTagText(choice), nameof(choice));
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
            m_value = GetValue(choice);
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
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return new DerTaggedObject(false, m_tagNo, m_value);
        }
    }
}
