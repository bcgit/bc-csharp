using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * X.509 Section 9.8.3.
     * <br/>
     * This extension may be used as a public-key certificate extension, a CRL extension or an AVL extension. It shall contain
     * the algorithm identifier for the alternative digital signature algorithm used by the signer when creating an alternative
     * digital signature and by the relying party when validating the alternative digital signature.
     * <pre>
     * altSignatureAlgorithm EXTENSION ::= {
     *     SYNTAX AltSignatureAlgorithm
     *     IDENTIFIED BY id-ce-altSignatureAlgorithm }
     *
     * AltSignatureAlgorithm ::= AlgorithmIdentifier{{SupportedAlgorithms}}
     * </pre>
     * When the altSignatureAlgorithm extension is included in a particular value that is an instance of a data type that
     * supports extensions, the altSignatureValue extension shall also be included.
     * <br/>
     * NOTE 1 – By having a separate altSignatureAlgorithm extension, instead of having it combined with the
     * altSignatureValue extension, the alternative digital signature algorithm is protected by the alternative signature.
     * This extension may be flagged either as critical or as non-critical.
     * <br/>
     * NOTE 2 – It is recommended that it be flagged as non-critical. Flagging it as critical would require all relying parties to understand
     * the extension and the alternative public-key algorithms
     */
    public class AltSignatureAlgorithm
        : Asn1Encodable
    {
        private readonly AlgorithmIdentifier m_algorithm;

        public static AltSignatureAlgorithm GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AltSignatureAlgorithm altSignatureAlgorithm)
                return altSignatureAlgorithm;
            return new AltSignatureAlgorithm(AlgorithmIdentifier.GetInstance(obj));
        }

        public static AltSignatureAlgorithm GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(AlgorithmIdentifier.GetInstance(taggedObject, declaredExplicit));
        }

        public static AltSignatureAlgorithm FromExtensions(X509Extensions extensions)
        {
            return GetInstance(
                X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.AltSignatureAlgorithm));
        }

        public AltSignatureAlgorithm(AlgorithmIdentifier algorithm)
        {
            m_algorithm = algorithm;
        }

        public AltSignatureAlgorithm(DerObjectIdentifier algorithm, Asn1Encodable parameters)
        {
            m_algorithm = new AlgorithmIdentifier(algorithm, parameters);
        }

        public AlgorithmIdentifier Algorithm => m_algorithm;

        public override Asn1Object ToAsn1Object()
        {
            return m_algorithm.ToAsn1Object();
        }
    }
}
