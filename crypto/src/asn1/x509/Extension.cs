using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /*
     *  Extension ::= SEQUENCE {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING
     *                  -- contains the DER encoding of an ASN.1 value
     *                  -- corresponding to the extension type identified
     *                  -- by extnID
     *  }
     */
    public class Extension
        : Asn1Encodable
    {
        private static readonly DerBoolean DefaultCritical = DerBoolean.False;

        public static Extension GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Extension extension)
                return extension;
            return new Extension(Asn1Sequence.GetInstance(obj));
        }

        public static Extension GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extension(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Extension GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extension(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_extnID;
        private readonly DerBoolean m_critical;
        private readonly Asn1OctetString m_extnValue;

        private Extension(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_extnID = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_critical = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DefaultCritical;
            m_extnValue = Asn1OctetString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Extension(DerObjectIdentifier extnID, DerBoolean critical, Asn1OctetString extnValue)
        {
            m_extnID = extnID ?? throw new ArgumentNullException(nameof(extnID));
            m_critical = critical ?? DefaultCritical;
            m_extnValue = extnValue ?? throw new ArgumentNullException(nameof(extnValue));
        }

        public DerBoolean Critical => m_critical;

        public DerObjectIdentifier ExtnID => m_extnID;

        public Asn1OctetString ExtnValue => m_extnValue;

        public override Asn1Object ToAsn1Object()
        {
            return DefaultCritical.Equals(m_critical)
                ?   new DerSequence(m_extnID, m_extnValue)
                :   new DerSequence(m_extnID, m_critical, m_extnValue);
        }

        public X509Extension GetX509Extension() => new X509Extension(m_critical, m_extnValue);
    }
}
