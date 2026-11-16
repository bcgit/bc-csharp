using System;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
    * The SemanticsInformation object.
    * <pre>
    *       SemanticsInformation ::= SEQUENCE {
    *         semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
    *         nameRegistrationAuthorities NameRegistrationAuthorities
    *                                                         OPTIONAL }
    *         (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
    *          WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
    *
    *     NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF
    *         GeneralName
    * </pre>
    */
    public class SemanticsInformation
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SemanticsInformation"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SemanticsInformation"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SemanticsInformation"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SemanticsInformation GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SemanticsInformation semanticsInformation)
                return semanticsInformation;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SemanticsInformation(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SemanticsInformation"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SemanticsInformation"/>.</returns>
        public static SemanticsInformation GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SemanticsInformation(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SemanticsInformation"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SemanticsInformation"/>.</returns>
        public static SemanticsInformation GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SemanticsInformation(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_semanticsIdentifier;
        private readonly GeneralName[] m_nameRegistrationAuthorities;

        /// <summary>Create a new <see cref="SemanticsInformation"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public SemanticsInformation(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;

            // NOTE: At least one of 'semanticsIdentifier' or 'nameRegistrationAuthorities' must be present
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_semanticsIdentifier = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
            m_nameRegistrationAuthorities = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional)
                ?.MapElements(GeneralName.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SemanticsInformation"/>.</summary>
        /// <param name="semanticsIdentifier">The semantics identifier.</param>
        public SemanticsInformation(DerObjectIdentifier semanticsIdentifier)
            : this(semanticsIdentifier, null)
        {
        }

        /// <summary>Create a new <see cref="SemanticsInformation"/>.</summary>
        /// <param name="generalNames">The general names.</param>
        // TODO[api] Rename parameter
        public SemanticsInformation(GeneralName[] generalNames)
            : this(null, generalNames)
        {
        }

        /// <summary>Create a new <see cref="SemanticsInformation"/>.</summary>
        /// <param name="semanticsIdentifier">The semantics identifier.</param>
        /// <param name="generalNames">The general names.</param>
        public SemanticsInformation(DerObjectIdentifier semanticsIdentifier, GeneralName[] generalNames)
        {
            if (semanticsIdentifier == null && generalNames == null)
                throw new ArgumentException("At least one option must be present");

            m_semanticsIdentifier = semanticsIdentifier;
            m_nameRegistrationAuthorities = generalNames;
        }

        /// <summary>Gets the semantics identifier.</summary>
        public DerObjectIdentifier SemanticsIdentifier  => m_semanticsIdentifier;

        /// <summary>Return the name registration authorities.</summary>
        public GeneralName[] GetNameRegistrationAuthorities() => m_nameRegistrationAuthorities;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptional(m_semanticsIdentifier);
            v.AddOptional(DerSequence.FromElementsOptional(m_nameRegistrationAuthorities));
            return new DerSequence(v);
        }
    }
}
