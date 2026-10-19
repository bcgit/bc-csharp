using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>The CommitmentTypeIndication structure of ETSI TS 101 733.</summary>
    public class CommitmentTypeIndication
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CommitmentTypeIndication"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CommitmentTypeIndication"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CommitmentTypeIndication"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="CommitmentTypeIndication"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CommitmentTypeIndication"/>.</returns>
        public static CommitmentTypeIndication GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeIndication(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CommitmentTypeIndication"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CommitmentTypeIndication"/>.</returns>
        public static CommitmentTypeIndication GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CommitmentTypeIndication(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_commitmentTypeId;
        private readonly Asn1Sequence m_commitmentTypeQualifier;

        /// <summary>Create a new <see cref="CommitmentTypeIndication"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public CommitmentTypeIndication(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_commitmentTypeId = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_commitmentTypeQualifier = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CommitmentTypeIndication"/>.</summary>
        /// <param name="commitmentTypeId">The commitment type id.</param>
        public CommitmentTypeIndication(DerObjectIdentifier commitmentTypeId)
            : this(commitmentTypeId, null)
        {
        }

        /// <summary>Create a new <see cref="CommitmentTypeIndication"/>.</summary>
        /// <param name="commitmentTypeId">The commitment type id.</param>
        /// <param name="commitmentTypeQualifier">The commitment type qualifier.</param>
        public CommitmentTypeIndication(DerObjectIdentifier commitmentTypeId, Asn1Sequence commitmentTypeQualifier)
        {
            m_commitmentTypeId = commitmentTypeId ?? throw new ArgumentNullException(nameof(commitmentTypeId));
            m_commitmentTypeQualifier = commitmentTypeQualifier;
        }

        /// <summary>Gets the commitment type ID.</summary>
        public DerObjectIdentifier CommitmentTypeID => m_commitmentTypeId;

        /// <summary>Gets the commitment type qualifier.</summary>
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
