using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    public class Gost28147Parameters
        : Asn1Encodable
    {
		public static Gost28147Parameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost28147Parameters gost28147Parameters)
                return gost28147Parameters;
            return new Gost28147Parameters(Asn1Sequence.GetInstance(obj));
        }

        public static Gost28147Parameters GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Gost28147Parameters(Asn1Sequence.GetInstance(obj, explicitly));

        public static Gost28147Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost28147Parameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        private Gost28147Parameters(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // TODO Validate length of 8?
			m_iv = Asn1OctetString.GetInstance(seq[0]);
            m_encryptionParamSet = DerObjectIdentifier.GetInstance(seq[1]);
        }

        public Gost28147Parameters(Asn1OctetString iv, DerObjectIdentifier encryptionParamSet)
        {
            m_iv = iv ?? throw new ArgumentNullException(nameof(iv));
            m_encryptionParamSet = encryptionParamSet ?? throw new ArgumentNullException(nameof(encryptionParamSet));
        }

        public Asn1OctetString IV => m_iv;

        public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

		/**
         * <pre>
         * Gost28147-89-Parameters ::=
         *               SEQUENCE {
         *                       iv                   Gost28147-89-IV,
         *                       encryptionParamSet   OBJECT IDENTIFIER
         *                }
         *
         *   Gost28147-89-IV ::= OCTET STRING (SIZE (8))
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_iv, m_encryptionParamSet);
    }
}
