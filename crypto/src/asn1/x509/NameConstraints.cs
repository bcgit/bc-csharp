using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>
    /// <code>
    /// NameConstraints ::= SEQUENCE {
    ///     permittedSubtrees   [0] GeneralSubtrees OPTIONAL,
    ///     excludedSubtrees    [1] GeneralSubtrees OPTIONAL
    /// }
    /// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    /// </code>
    /// </remarks>
    public class NameConstraints
        : Asn1Encodable
    {
        public static NameConstraints GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is NameConstraints nameConstraints)
                return nameConstraints;
#pragma warning disable CS0618 // Type or member is obsolete
            return new NameConstraints(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static NameConstraints GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NameConstraints(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static NameConstraints GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NameConstraints(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_permitted, m_excluded;

        [Obsolete("Use 'GetInstance' instead")]
        public NameConstraints(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_permitted = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Sequence.GetTagged);
            m_excluded = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            Validate();
        }

        public NameConstraints(GeneralSubtree[] permitted, GeneralSubtree[] excluded)
        {
            m_permitted = DerSequence.FromElementsOptional(permitted);
            m_excluded = DerSequence.FromElementsOptional(excluded);

            Validate();
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// permitted and excluded are Vectors of GeneralSubtree objects.
        /// </remarks>
        /// <param name="permitted">Permitted subtrees</param>
        /// <param name="excluded">Excluded subtrees</param>
        public NameConstraints(IList<GeneralSubtree> permitted, IList<GeneralSubtree> excluded)
        {
            m_permitted = CreateSequence(permitted);
            m_excluded = CreateSequence(excluded);

            Validate();
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// permitted and excluded are Vectors of GeneralSubtree objects.
        /// </remarks>
        /// <param name="permitted">Permitted subtrees</param>
        /// <param name="excluded">Excluded subtrees</param>
        public NameConstraints(IReadOnlyCollection<GeneralSubtree> permitted,
            IReadOnlyCollection<GeneralSubtree> excluded)
        {
            m_permitted = CreateSequence(permitted);
            m_excluded = CreateSequence(excluded);

            Validate();
        }

        public Asn1Sequence PermittedSubtrees => m_permitted;

        public Asn1Sequence ExcludedSubtrees => m_excluded;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_permitted);
            v.AddOptionalTagged(false, 1, m_excluded);
            return new DerSequence(v);
        }

        private void Validate()
        {
            // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

            if (m_permitted != null && m_permitted.Count < 1)
                throw new ArgumentException("GeneralSubtrees SEQUENCE has SIZE < minimum 1", "permittedSubtrees");
            if (m_excluded != null && m_excluded.Count < 1)
                throw new ArgumentException("GeneralSubtrees SEQUENCE has SIZE < minimum 1", "excludedSubtrees");
        }

        private static DerSequence CreateSequence(IList<GeneralSubtree> subtrees) =>
            subtrees == null ? null : DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(subtrees));

        private static DerSequence CreateSequence(IReadOnlyCollection<GeneralSubtree> subtrees) =>
            subtrees == null ? null : DerSequence.FromCollection(subtrees);
    }
}
