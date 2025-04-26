using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
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
        }

        /**
         * Constructor from a given details.
         *
         * <p>permitted and excluded are Vectors of GeneralSubtree objects.</p>
         *
         * @param permitted Permitted subtrees
         * @param excluded Excluded subtrees
         */
        public NameConstraints(IList<GeneralSubtree> permitted, IList<GeneralSubtree> excluded)
        {
            m_permitted = CreateSequence(permitted);
            m_excluded = CreateSequence(excluded);
        }

        /**
         * Constructor from a given details.
         *
         * <p>permitted and excluded are Vectors of GeneralSubtree objects.</p>
         *
         * @param permitted Permitted subtrees
         * @param excluded Excluded subtrees
         */
        public NameConstraints(IReadOnlyCollection<GeneralSubtree> permitted,
            IReadOnlyCollection<GeneralSubtree> excluded)
        {
            m_permitted = CreateSequence(permitted);
            m_excluded = CreateSequence(excluded);
        }

        public Asn1Sequence PermittedSubtrees => m_permitted;

        public Asn1Sequence ExcludedSubtrees => m_excluded;

        /*
         * NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
         * OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_permitted);
            v.AddOptionalTagged(false, 1, m_excluded);
            return new DerSequence(v);
        }

        private static DerSequence CreateSequence(IList<GeneralSubtree> subtrees) =>
            subtrees == null ? null : DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(subtrees));

        private static DerSequence CreateSequence(IReadOnlyCollection<GeneralSubtree> subtrees) =>
            subtrees == null ? null : DerSequence.FromCollection(subtrees);
    }
}
