using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    public class CommitmentTypeIndication
        : Asn1Encodable
    {
        public static CommitmentTypeIndication GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CommitmentTypeIndication commitmentTypeIndication)
                return commitmentTypeIndication;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeIndication(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CommitmentTypeIndication GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeIndication(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_commitmentTypeId;
        private readonly Asn1Sequence m_commitmentTypeQualifier;

        [Obsolete("Use 'GetInstance' instead")]
        public CommitmentTypeIndication(Asn1Sequence seq)
        {
            int count = seq.Count;
			if (count < 1 || count > 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_commitmentTypeId = DerObjectIdentifier.GetInstance(seq[0]);

			if (count > 1)
            {
                m_commitmentTypeQualifier = Asn1Sequence.GetInstance(seq[1]);
            }
        }

		public CommitmentTypeIndication(DerObjectIdentifier commitmentTypeId)
			: this(commitmentTypeId, null)
        {
        }

		public CommitmentTypeIndication(DerObjectIdentifier commitmentTypeId, Asn1Sequence commitmentTypeQualifier)
        {
			m_commitmentTypeId = commitmentTypeId ?? throw new ArgumentNullException(nameof(commitmentTypeId));
            m_commitmentTypeQualifier = commitmentTypeQualifier;
        }

        public DerObjectIdentifier CommitmentTypeID => m_commitmentTypeId;

        public Asn1Sequence CommitmentTypeQualifier => m_commitmentTypeQualifier;

		/**
        * <pre>
        * CommitmentTypeIndication ::= SEQUENCE {
        *      commitmentTypeId   CommitmentTypeIdentifier,
        *      commitmentTypeQualifier   SEQUENCE SIZE (1..MAX) OF
        *              CommitmentTypeQualifier OPTIONAL }
        * </pre>
        */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_commitmentTypeId);
            v.AddOptional(m_commitmentTypeQualifier);
			return new DerSequence(v);
        }
    }
}
