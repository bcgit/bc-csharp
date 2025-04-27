using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class PollReqContent
        : Asn1Encodable
    {
        public static PollReqContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PollReqContent pollReqContent)
                return pollReqContent;
            return new PollReqContent(Asn1Sequence.GetInstance(obj));
        }

        public static PollReqContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PollReqContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PollReqContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PollReqContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private PollReqContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /**
         * Create a pollReqContent for a single certReqId.
         *
         * @param certReqId the certificate request ID.
         */
        public PollReqContent(DerInteger certReqId)
            : this(DerSequence.FromElement(new DerSequence(certReqId)))
        {
        }

        /**
         * Create a pollReqContent for a multiple certReqIds.
         *
         * @param certReqIds the certificate request IDs.
         */
        public PollReqContent(DerInteger[] certReqIds)
            : this(DerSequence.WithElements(CollectionUtilities.Map(certReqIds, id => new DerSequence(id))))
        {
        }

        /**
         * Create a pollReqContent for a single certReqId.
         *
         * @param certReqId the certificate request ID.
         */
        public PollReqContent(BigInteger certReqId)
            : this(new DerInteger(certReqId))
        {
        }

        /**
         * Create a pollReqContent for a multiple certReqIds.
         *
         * @param certReqIds the certificate request IDs.
         */
        public PollReqContent(BigInteger[] certReqIds)
            : this(CollectionUtilities.Map(certReqIds, id => new DerInteger(id)))
        {
        }

        public virtual DerInteger[][] GetCertReqIDs() =>
            m_content.MapElements(element => Asn1Sequence.GetInstance(element).MapElements(DerInteger.GetInstance));

        public virtual BigInteger[] GetCertReqIDValues() =>
            m_content.MapElements(element => DerInteger.GetInstance(Asn1Sequence.GetInstance(element)[0]).Value);

        /**
         * <pre>
         * PollReqContent ::= SEQUENCE OF SEQUENCE {
         *                        certReqId              INTEGER
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
