using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /**
     * Password-based MAC value for use with POPOSigningKeyInput.
     */
    public class PKMacValue
        : Asn1Encodable
    {
        public static PKMacValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PKMacValue pkMacValue)
                return pkMacValue;
            return new PKMacValue(Asn1Sequence.GetInstance(obj));
        }

        public static PKMacValue GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new PKMacValue(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly AlgorithmIdentifier m_algID;
        private readonly DerBitString m_macValue;

        private PKMacValue(Asn1Sequence seq)
        {
            m_algID = AlgorithmIdentifier.GetInstance(seq[0]);
            m_macValue = DerBitString.GetInstance(seq[1]);
        }

        /**
         * Creates a new PKMACValue.
         * @param params parameters for password-based MAC
         * @param value MAC of the DER-encoded SubjectPublicKeyInfo
         */
        public PKMacValue(PbmParameter pbmParams, DerBitString macValue)
            : this(new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, pbmParams), macValue)
        {
        }

        /**
         * Creates a new PKMACValue.
         * @param aid CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter
         * @param value MAC of the DER-encoded SubjectPublicKeyInfo
         */
        public PKMacValue(AlgorithmIdentifier algID, DerBitString macValue)
        {
            m_algID = algID;
            m_macValue = macValue;
        }

        public virtual AlgorithmIdentifier AlgID => m_algID;

        public virtual DerBitString MacValue => m_macValue;

        /**
         * <pre>
         * PKMACValue ::= SEQUENCE {
         *      algId  AlgorithmIdentifier,
         *      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
         *      -- parameter value is PBMParameter
         *      value  BIT STRING }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algID, m_macValue);
    }
}
