using System;
using System.Collections.Generic;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <code>NoticeReference</code> class, used in
     * <code>CertificatePolicies</code> X509 V3 extensions
     * (in policy qualifiers).
     *
     * <pre>
     *  NoticeReference ::= Sequence {
     *      organization     DisplayText,
     *      noticeNumbers    Sequence OF Integer }
     *
     * </pre>
     *
     * @see PolicyQualifierInfo
     * @see PolicyInformation
     */
    public class NoticeReference
        : Asn1Encodable
    {
        public static NoticeReference GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is NoticeReference noticeReference)
                return noticeReference;
            return new NoticeReference(Asn1Sequence.GetInstance(obj));
        }

        public static NoticeReference GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new NoticeReference(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static NoticeReference GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is NoticeReference noticeReference)
                return noticeReference;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new NoticeReference(asn1Sequence);

            return null;
        }

        public static NoticeReference GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new NoticeReference(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DisplayText m_organization;
        private readonly Asn1Sequence m_noticeNumbers;

        /**
         * Creates a new <code>NoticeReference</code> instance.
         * <p>Useful for reconstructing a <code>NoticeReference</code>
         * instance from its encodable/encoded form.</p>
         *
         * @param as an <code>Asn1Sequence</code> value obtained from either
         * calling @{link ToAsn1Object()} for a <code>NoticeReference</code>
         * instance or from parsing it from a Der-encoded stream.
         */
        private NoticeReference(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_organization = DisplayText.GetInstance(seq[0]);
            m_noticeNumbers = Asn1Sequence.GetInstance(seq[1]);
        }

        /**
         * Creates a new <code>NoticeReference</code> instance.
         *
         * @param organization a <code>String</code> value
         * @param numbers a <code>Vector</code> value
         */
        public NoticeReference(string organization, IList<object> numbers)
            : this(organization, ConvertVector(numbers))
        {
        }

        /**
        * Creates a new <code>NoticeReference</code> instance.
        *
        * @param organization a <code>String</code> value
        * @param noticeNumbers an <code>ASN1EncodableVector</code> value
        */
        public NoticeReference(string organization, Asn1EncodableVector noticeNumbers)
            : this(new DisplayText(organization), noticeNumbers)
        {
        }

        /**
         * Creates a new <code>NoticeReference</code> instance.
         *
         * @param organization displayText
         * @param noticeNumbers an <code>ASN1EncodableVector</code> value
         */
        public NoticeReference(DisplayText organization, Asn1EncodableVector noticeNumbers)
        {
            m_organization = organization ?? throw new ArgumentNullException(nameof(organization));
            m_noticeNumbers = new DerSequence(noticeNumbers);
        }

        public virtual DisplayText Organization => m_organization;

        public virtual DerInteger[] GetNoticeNumbers() => m_noticeNumbers.MapElements(DerInteger.GetInstance);

        /**
         * Describe <code>ToAsn1Object</code> method here.
         *
         * @return a <code>Asn1Object</code> value
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_organization, m_noticeNumbers);

        private static Asn1EncodableVector ConvertVector(IList<object> numbers)
        {
            Asn1EncodableVector av = new Asn1EncodableVector(numbers.Count);
            foreach (object o in numbers)
            {
                DerInteger di;
                if (o is BigInteger big)
                {
                    di = new DerInteger(big);
                }
                else if (o is int i)
                {
                    di = new DerInteger(i);
                }
                else
                {
                    throw new ArgumentException();
                }

                av.Add(di);
            }
            return av;
        }
    }
}
