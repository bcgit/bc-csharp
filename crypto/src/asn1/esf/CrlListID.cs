using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CRLListID ::= SEQUENCE {
    ///     crls    SEQUENCE OF CrlValidatedID
    /// }
    /// </code>
    /// </remarks>
    public class CrlListID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlListID"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlListID"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlListID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlListID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlListID crlListID)
                return crlListID;
            return new CrlListID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlListID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlListID"/>.</returns>
        public static CrlListID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlListID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlListID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlListID"/>.</returns>
        public static CrlListID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlListID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_crls;

        private CrlListID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_crls = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_crls.MapElements(CrlValidatedID.GetInstance); // Validate

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CrlListID"/>.</summary>
        /// <param name="crls">The crls.</param>
        public CrlListID(params CrlValidatedID[] crls)
        {
            m_crls = DerSequence.FromElements(crls);
        }

        /// <summary>Create a new <see cref="CrlListID"/>.</summary>
        /// <param name="crls">The crls.</param>
        public CrlListID(IEnumerable<CrlValidatedID> crls)
        {
            if (crls == null)
                throw new ArgumentNullException(nameof(crls));

            m_crls = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crls));
        }

        /// <summary>Create a new <see cref="CrlListID"/>.</summary>
        /// <param name="crls">The crls.</param>
        public CrlListID(IReadOnlyCollection<CrlValidatedID> crls)
        {
            if (crls == null)
                throw new ArgumentNullException(nameof(crls));

            m_crls = DerSequence.FromCollection(crls);
        }

        /// <summary>Return the crls.</summary>
        public CrlValidatedID[] GetCrls() => m_crls.MapElements(CrlValidatedID.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => DerSequence.FromElement(m_crls);
    }
}
