using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * X.509 Section 9.8.4.
     * <br/>
     * This extension may be used as a public-key certificate extension, a CRL extension or an AVL extension.
     * This alternative signature shall be created by the issuer using its alternative private key, and it shall be verified using the
     * alternative public key of the issuer.
     * <pre>
     * altSignatureValue EXTENSION ::= {
     *     SYNTAX AltSignatureValue
     *     IDENTIFIED BY id-ce-altSignatureValue }
     *
     * AltSignatureValue ::= BIT STRING
     * </pre>
     * This extension can only be created by a signer holding a multiple cryptographic algorithms public-key certificate. When
     * creating the alternative digital signature on an issued public-key certificate or CRL, the signer shall use its alternative
     * private key.
     * <br/>
     * The procedures for creating and validating alternative digital signatures are specified in:
     * <ul>
     * <li>clause 7.2.2 for public-key certificates;</li>
     * <li>clause 7.10.3 for CRLs: and</li>
     * <li>clause 11.4 for AVLs.</li>
     * </ul>
     */
    public class AltSignatureValue
        : Asn1Encodable
    {
        private readonly DerBitString m_signature;

        public static AltSignatureValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AltSignatureValue altSignatureValue)
                return altSignatureValue;
            return new AltSignatureValue(DerBitString.GetInstance(obj));
        }

        public static AltSignatureValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(DerBitString.GetInstance(taggedObject, declaredExplicit));
        }

        public static AltSignatureValue FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.AltSignatureValue));
        }

        private AltSignatureValue(DerBitString signature)
        {
            m_signature = signature;
        }

        public AltSignatureValue(byte[] signature)
        {
            m_signature = new DerBitString(signature);
        }

        public DerBitString Signature => m_signature;

        public override Asn1Object ToAsn1Object()
        {
            return m_signature;
        }
    }
}
