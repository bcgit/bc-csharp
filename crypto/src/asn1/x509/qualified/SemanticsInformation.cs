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
        public static SemanticsInformation GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SemanticsInformation semanticsInformation)
                return semanticsInformation;
            return new SemanticsInformation(Asn1Sequence.GetInstance(obj));
        }

        public static SemanticsInformation GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SemanticsInformation(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SemanticsInformation GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SemanticsInformation(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_semanticsIdentifier;
        private readonly GeneralName[] m_nameRegistrationAuthorities;

        public SemanticsInformation(Asn1Sequence seq)
        {
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

        public SemanticsInformation(DerObjectIdentifier semanticsIdentifier)
            : this(semanticsIdentifier, null)
        {
        }

        // TODO[api] Rename parameter
        public SemanticsInformation(GeneralName[] generalNames)
            : this(null, generalNames)
        {
        }

        public SemanticsInformation(DerObjectIdentifier semanticsIdentifier, GeneralName[] generalNames)
        {
            if (semanticsIdentifier == null && generalNames == null)
                throw new ArgumentException("At least one option must be present");

            m_semanticsIdentifier = semanticsIdentifier;
            m_nameRegistrationAuthorities = generalNames;
        }

		public DerObjectIdentifier SemanticsIdentifier  => m_semanticsIdentifier;

        public GeneralName[] GetNameRegistrationAuthorities() => m_nameRegistrationAuthorities;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptional(m_semanticsIdentifier);
            v.AddOptional(DerSequence.FromElementsOptional(m_nameRegistrationAuthorities));
            return new DerSequence(v);
        }
    }
}
