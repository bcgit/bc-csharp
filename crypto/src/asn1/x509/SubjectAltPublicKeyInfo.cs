using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * X.509 Section 9.8.2.
     * <br/>
     * This public-key certificate extension, when present, shall contain the subject’s alternative public key information
     * <pre>
     * subjectAltPublicKeyInfo EXTENSION ::= {
     *      SYNTAX SubjectAltPublicKeyInfo
     *      IDENTIFIED BY id-ce-subjectAltPublicKeyInfo }
     *
     * SubjectAltPublicKeyInfo ::= SEQUENCE {
     *     algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
     *     subjectAltPublicKey BIT STRING }
     * </pre>
     * The SubjectAltPublicKeyInfo data type has the following components:
     * <ul>
     * <li>the algorithm subcomponent, which shall hold the algorithm that this public key is an instance of</li>
     * <li>the subjectAltPublicKey subcomponent, which shall hold the alternative public key</li>
     * </ul>
     * This extension may be flagged as critical or as non-critical.
     * <br/>
     * NOTE – It is recommended that it be flagged as non-critical. Flagging it as critical would require relying parties to understand this
     * extension and the alternative public-key algorithm.
     */
    public class SubjectAltPublicKeyInfo
        : Asn1Encodable
    {
        private readonly AlgorithmIdentifier m_algorithm;
        private readonly DerBitString m_subjectAltPublicKey;

        public static SubjectAltPublicKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectAltPublicKeyInfo subjectAltPublicKeyInfo)
                return subjectAltPublicKeyInfo;
            return new SubjectAltPublicKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        public static SubjectAltPublicKeyInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public static SubjectAltPublicKeyInfo FromExtensions(X509Extensions extensions)
        {
            return GetInstance(
                X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.SubjectAltPublicKeyInfo));
        }

        private SubjectAltPublicKeyInfo(Asn1Sequence seq)
        {
            if (seq.Count != 2)
                throw new ArgumentException("extension should contain only 2 elements");

            m_algorithm = AlgorithmIdentifier.GetInstance(seq[0]);
            m_subjectAltPublicKey = DerBitString.GetInstance(seq[1]);
        }

        public SubjectAltPublicKeyInfo(AlgorithmIdentifier algorithm, DerBitString subjectAltPublicKey)
        {
            m_algorithm = algorithm;
            m_subjectAltPublicKey = subjectAltPublicKey;
        }

        public SubjectAltPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            m_algorithm = subjectPublicKeyInfo.AlgorithmID;
            m_subjectAltPublicKey = subjectPublicKeyInfo.PublicKeyData;
        }

        public AlgorithmIdentifier Algorithm => Algorithm;

        public DerBitString SubjectAltPublicKey => m_subjectAltPublicKey;

        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(m_algorithm, m_subjectAltPublicKey);
        }
    }
}
