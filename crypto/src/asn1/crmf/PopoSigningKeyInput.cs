using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class PopoSigningKeyInput
        : Asn1Encodable
    {
        public static PopoSigningKeyInput GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoSigningKeyInput popoSigningKeyInput)
                return popoSigningKeyInput;
            return new PopoSigningKeyInput(Asn1Sequence.GetInstance(obj));
        }

        public static PopoSigningKeyInput GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new PopoSigningKeyInput(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly GeneralName m_sender;
        private readonly PKMacValue m_publicKeyMac;
        private readonly SubjectPublicKeyInfo m_publicKey;

        private PopoSigningKeyInput(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            Asn1Encodable authInfo = (Asn1Encodable)seq[0];

            if (authInfo is Asn1TaggedObject tagObj)
            {
                m_sender = GeneralName.GetInstance(Asn1Utilities.GetExplicitContextBaseObject(tagObj, 0));
            }
            else
            {
                m_publicKeyMac = PKMacValue.GetInstance(authInfo);
            }

            m_publicKey = SubjectPublicKeyInfo.GetInstance(seq[1]);
        }

        /** Creates a new PopoSigningKeyInput with sender name as authInfo. */
        public PopoSigningKeyInput(GeneralName sender, SubjectPublicKeyInfo spki)
        {
            m_sender = sender ?? throw new ArgumentNullException(nameof(sender));
            m_publicKey = spki ?? throw new ArgumentNullException(nameof(spki));
        }

        /** Creates a new PopoSigningKeyInput using password-based MAC. */
        public PopoSigningKeyInput(PKMacValue pkmac, SubjectPublicKeyInfo spki)
        {
            m_publicKeyMac = pkmac ?? throw new ArgumentNullException(nameof(pkmac));
            m_publicKey = spki ?? throw new ArgumentNullException(nameof(spki));
        }

        /** Returns the sender field, or null if authInfo is publicKeyMac */
        public virtual GeneralName Sender => m_sender;

        /** Returns the publicKeyMac field, or null if authInfo is sender */
        public virtual PKMacValue PublicKeyMac => m_publicKeyMac;

        public virtual SubjectPublicKeyInfo PublicKey => m_publicKey;

        /**
         * <pre>
         * PopoSigningKeyInput ::= SEQUENCE {
         *        authInfo             CHOICE {
         *                                 sender              [0] GeneralName,
         *                                 -- used only if an authenticated identity has been
         *                                 -- established for the sender (e.g., a DN from a
         *                                 -- previously-issued and currently-valid certificate
         *                                 publicKeyMac        PKMacValue },
         *                                 -- used if no authenticated GeneralName currently exists for
         *                                 -- the sender; publicKeyMac contains a password-based MAC
         *                                 -- on the DER-encoded value of publicKey
         *        publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);

            if (m_sender != null)
            {
                v.Add(new DerTaggedObject(true, 0, m_sender));
            }
            else
            {
                v.Add(m_publicKeyMac);
            }

            v.Add(m_publicKey);

            return new DerSequence(v);
        }
    }
}
