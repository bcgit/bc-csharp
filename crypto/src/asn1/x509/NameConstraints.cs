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

        public static NameConstraints GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
#pragma warning disable CS0618 // Type or member is obsolete
            new NameConstraints(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete

        public static NameConstraints GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
#pragma warning disable CS0618 // Type or member is obsolete
            new NameConstraints(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete

        private readonly GeneralSubtrees m_permittedSubtrees, m_excludedSubtrees;

        [Obsolete("Use 'GetInstance' instead")]
        public NameConstraints(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_permittedSubtrees = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                GeneralSubtrees.GetTagged);
            m_excludedSubtrees = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false,
                GeneralSubtrees.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <param name="permittedSubtrees">Permitted subtrees</param>
        /// <param name="excludedSubtrees">Excluded subtrees</param>
        public NameConstraints(GeneralSubtrees permittedSubtrees, GeneralSubtrees excludedSubtrees)
        {
            m_permittedSubtrees = permittedSubtrees;
            m_excludedSubtrees = excludedSubtrees;
        }

        [Obsolete("Use 'GeneralSubtrees' constructor")]
        public NameConstraints(GeneralSubtree[] permitted, GeneralSubtree[] excluded)
        {
            m_permittedSubtrees = permitted == null ? null : new GeneralSubtrees(permitted);
            m_excludedSubtrees = excluded == null ? null : new GeneralSubtrees(excluded);
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// permitted and excluded are Vectors of GeneralSubtree objects.
        /// </remarks>
        /// <param name="permitted">Permitted subtrees</param>
        /// <param name="excluded">Excluded subtrees</param>
        [Obsolete("Use 'GeneralSubtrees' constructor")]
        public NameConstraints(IList<GeneralSubtree> permitted, IList<GeneralSubtree> excluded)
        {
            // TODO[asn1] Passes IList as IEnumerable, so loses Count
            m_permittedSubtrees = permitted == null ? null : new GeneralSubtrees(permitted);
            m_excludedSubtrees = excluded == null ? null : new GeneralSubtrees(excluded);
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// permitted and excluded are Vectors of GeneralSubtree objects.
        /// </remarks>
        /// <param name="permitted">Permitted subtrees</param>
        /// <param name="excluded">Excluded subtrees</param>
        [Obsolete("Use 'GeneralSubtrees' constructor")]
        public NameConstraints(IReadOnlyCollection<GeneralSubtree> permitted,
            IReadOnlyCollection<GeneralSubtree> excluded)
        {
            m_permittedSubtrees = permitted == null ? null : new GeneralSubtrees(permitted);
            m_excludedSubtrees = excluded == null ? null : new GeneralSubtrees(excluded);
        }

        [Obsolete("Use 'PermittedSubtreesValue' instead")]
        public Asn1Sequence PermittedSubtrees => m_permittedSubtrees?.Elements;

        public GeneralSubtrees PermittedSubtreesValue => m_permittedSubtrees;

        [Obsolete("Use 'ExcludedSubtreesValue' instead")]
        public Asn1Sequence ExcludedSubtrees => m_excludedSubtrees?.Elements;

        public GeneralSubtrees ExcludedSubtreesValue => m_excludedSubtrees;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_permittedSubtrees);
            v.AddOptionalTagged(false, 1, m_excludedSubtrees);
            return new DerSequence(v);
        }
    }
}
