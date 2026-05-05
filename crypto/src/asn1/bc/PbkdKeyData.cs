using System;

namespace Org.BouncyCastle.Asn1.BC
{
    /**
     * Carrier for the contents of a {@link javax.crypto.interfaces.PBEKey} stored
     * in a BCFKS keystore.
     * <pre>
     *     PbkdKeyData ::= SEQUENCE {
     *         keyAlgorithm   UTF8String,
     *         password       OCTET STRING,
     *         salt           [0] IMPLICIT OCTET STRING OPTIONAL,
     *         iterationCount [1] IMPLICIT INTEGER OPTIONAL,
     *         encoded        [2] IMPLICIT OCTET STRING OPTIONAL
     *     }
     * </pre>
     */
    public class PbkdKeyData
        : Asn1Encodable
    {
        public static PbkdKeyData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbkdKeyData pbkdKeyData)
                return pbkdKeyData;
            return new PbkdKeyData(Asn1Sequence.GetInstance(obj));
        }

        public static PbkdKeyData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbkdKeyData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PbkdKeyData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbkdKeyData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerUtf8String m_keyAlgorithm;
        private readonly Asn1OctetString m_password;
        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_iterationCount;
        private readonly Asn1OctetString m_encoded;

        public PbkdKeyData(DerUtf8String keyAlgorithm, Asn1OctetString password, Asn1OctetString salt,
            DerInteger iterationCount, Asn1OctetString encoded)
        {
            m_keyAlgorithm = keyAlgorithm ?? throw new ArgumentNullException(nameof(keyAlgorithm));
            m_password = password ?? throw new ArgumentNullException(nameof(password));
        }

        private PbkdKeyData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyAlgorithm = DerUtf8String.GetInstance(seq[pos++]);
            m_password = Asn1OctetString.GetInstance(seq[pos++]);
            m_salt = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1OctetString.GetTagged);
            m_iterationCount = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetTagged);
            m_encoded = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1OctetString Encoded => m_encoded;

        public DerInteger IterationCount => m_iterationCount;

        public DerUtf8String KeyAlgorithm => m_keyAlgorithm;

        public Asn1OctetString Password => m_password;

        public Asn1OctetString Salt => m_salt;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_keyAlgorithm, m_password);
            v.AddOptionalTagged(false, 0, m_salt);
            v.AddOptionalTagged(false, 1, m_iterationCount);
            v.AddOptionalTagged(false, 2, m_encoded);
            return new DerSequence(v);
        }
    }
}
