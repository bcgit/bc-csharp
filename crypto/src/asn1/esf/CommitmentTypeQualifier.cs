using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /**
    * Commitment type qualifiers, used in the Commitment-Type-Indication attribute (RFC3126).
    *
    * <pre>
    *   CommitmentTypeQualifier ::= SEQUENCE {
    *       commitmentTypeIdentifier  CommitmentTypeIdentifier,
    *       qualifier          ANY DEFINED BY commitmentTypeIdentifier OPTIONAL }
    * </pre>
    */
    public class CommitmentTypeQualifier
        : Asn1Encodable
    {
        public static CommitmentTypeQualifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CommitmentTypeQualifier commitmentTypeQualifier)
                return commitmentTypeQualifier;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeQualifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CommitmentTypeQualifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeQualifier(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_commitmentTypeIdentifier;
        private readonly Asn1Encodable m_qualifier;

        /**
         * Creates a new <code>CommitmentTypeQualifier</code> instance.
         *
         * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
         */
        public CommitmentTypeQualifier(DerObjectIdentifier commitmentTypeIdentifier)
            : this(commitmentTypeIdentifier, null)
        {
        }

        /**
         * Creates a new <code>CommitmentTypeQualifier</code> instance.
         *
         * @param commitmentTypeIdentifier a <code>CommitmentTypeIdentifier</code> value
         * @param qualifier the qualifier, defined by the above field.
         */
        public CommitmentTypeQualifier(DerObjectIdentifier commitmentTypeIdentifier, Asn1Encodable qualifier)
        {
			m_commitmentTypeIdentifier = commitmentTypeIdentifier
                ?? throw new ArgumentNullException(nameof(commitmentTypeIdentifier));
            m_qualifier = qualifier;
        }

        /**
        * Creates a new <code>CommitmentTypeQualifier</code> instance.
        *
        * @param as <code>CommitmentTypeQualifier</code> structure
        * encoded as an Asn1Sequence.
        */
        [Obsolete("Use 'GetInstance' instead")]
        public CommitmentTypeQualifier(Asn1Sequence seq)
        {
            int count = seq.Count;
			if (count < 1 || count > 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_commitmentTypeIdentifier = DerObjectIdentifier.GetInstance(seq[0]);

			if (count > 1)
            {
                m_qualifier = seq[1];
            }
        }

        public DerObjectIdentifier CommitmentTypeIdentifier => m_commitmentTypeIdentifier;

        public Asn1Encodable QualifierData => m_qualifier;

        [Obsolete("Use 'QualifierData' instead")]
        public Asn1Object Qualifier => m_qualifier?.ToAsn1Object();

		/**
        * Returns a DER-encodable representation of this instance.
        *
        * @return a <code>Asn1Object</code> value
        */
		public override Asn1Object ToAsn1Object()
		{
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_commitmentTypeIdentifier);
            v.AddOptional(m_qualifier);
			return new DerSequence(v);
		}
    }
}
