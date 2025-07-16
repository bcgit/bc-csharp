using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * <pre>
     * EDIPartyName ::= Sequence {
     *      nameAssigner            [0]     DirectoryString OPTIONAL,
     *      partyName               [1]     DirectoryString }
     * </pre>
     */
    public class EdiPartyName
        : Asn1Encodable
    {
        public static EdiPartyName GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EdiPartyName ediPartyName)
                return ediPartyName;
            return new EdiPartyName(Asn1Sequence.GetInstance(obj));
        }

        public static EdiPartyName GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EdiPartyName(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DirectoryString m_nameAssigner;
        private readonly DirectoryString m_partyName;

        private EdiPartyName(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // DirectoryString is a CHOICE type, so use explicit tagging despite IMPLICIT TAGS
            m_nameAssigner = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DirectoryString.GetTagged);
            m_partyName = Asn1Utilities.ReadContextTagged(seq, ref pos, 1, true, DirectoryString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public EdiPartyName(DirectoryString nameAssigner, DirectoryString partyName)
        {
            m_nameAssigner = nameAssigner;
            m_partyName = partyName ?? throw new ArgumentNullException(nameof(partyName));
        }

        public DirectoryString NameAssigner => m_nameAssigner;

        public DirectoryString PartyName => m_partyName;

        public override Asn1Object ToAsn1Object()
        {
            return m_nameAssigner == null
                ?  new DerSequence(m_partyName)
                :  new DerSequence(m_nameAssigner, m_partyName);
        }
    }
}
