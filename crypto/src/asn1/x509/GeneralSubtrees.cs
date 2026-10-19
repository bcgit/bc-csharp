using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks><code>GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree</code></remarks>
    public sealed class GeneralSubtrees
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="GeneralSubtrees"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="GeneralSubtrees"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="GeneralSubtrees"/>, or null if <paramref name="obj"/> is null.</returns>
        public static GeneralSubtrees GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GeneralSubtrees generalSubtrees)
                return generalSubtrees;
            return new GeneralSubtrees(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="GeneralSubtrees"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GeneralSubtrees"/>.</returns>
        public static GeneralSubtrees GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GeneralSubtrees(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="GeneralSubtrees"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="GeneralSubtrees"/>, or null if <paramref name="element"/> is null.</returns>
        public static GeneralSubtrees GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is GeneralSubtrees generalSubtrees)
                return generalSubtrees;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new GeneralSubtrees(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="GeneralSubtrees"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GeneralSubtrees"/>.</returns>
        public static GeneralSubtrees GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GeneralSubtrees(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        private GeneralSubtrees(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_elements = DerSequence.Map(seq, GeneralSubtree.GetInstance);
        }

        /// <summary>Create a new <see cref="GeneralSubtrees"/>.</summary>
        /// <param name="generalSubtree">The general subtree.</param>
        public GeneralSubtrees(GeneralSubtree generalSubtree)
        {
            m_elements = DerSequence.FromElement(
                generalSubtree ?? throw new ArgumentNullException(nameof(generalSubtree)));
        }

        /// <summary>Create a new <see cref="GeneralSubtrees"/>.</summary>
        /// <param name="generalSubtrees">The general subtrees.</param>
        public GeneralSubtrees(params GeneralSubtree[] generalSubtrees)
        {
            if (Arrays.IsNullOrContainsNull(generalSubtrees))
                throw new ArgumentNullException(nameof(generalSubtrees), "cannot be null, or contain null");
            if (generalSubtrees.Length < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(generalSubtrees));

            m_elements = DerSequence.FromElements(generalSubtrees);
        }

        /// <summary>Create a new <see cref="GeneralSubtrees"/>.</summary>
        /// <param name="generalSubtrees">The general subtrees.</param>
        public GeneralSubtrees(IEnumerable<GeneralSubtree> generalSubtrees)
        {
            if (generalSubtrees == null)
                throw new ArgumentNullException(nameof(generalSubtrees));

            var elements = Asn1EncodableVector.FromEnumerable(generalSubtrees);

            if (elements.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(generalSubtrees));

            m_elements = DerSequence.FromVector(elements);
        }

        /// <summary>Create a new <see cref="GeneralSubtrees"/>.</summary>
        /// <param name="generalSubtrees">The general subtrees.</param>
        public GeneralSubtrees(IReadOnlyCollection<GeneralSubtree> generalSubtrees)
        {
            if (generalSubtrees == null)
                throw new ArgumentNullException(nameof(generalSubtrees));
            if (generalSubtrees.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(generalSubtrees));

            m_elements = DerSequence.FromCollection(generalSubtrees);
        }

        /// <summary>Gets the elements.</summary>
        public Asn1Sequence Elements => m_elements;

        /// <summary>Return the elements.</summary>
        public GeneralSubtree[] GetElements() => m_elements.MapElements(GeneralSubtree.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;
    }
}
