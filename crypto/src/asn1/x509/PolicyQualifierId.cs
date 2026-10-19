namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * PolicyQualifierId, used in the CertificatePolicies
     * X509V3 extension.
     *
     * <pre>
     *    id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
     *    id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
     *    id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
     *  PolicyQualifierId ::=
     *       OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
     * </pre>
     */
    public sealed class PolicyQualifierID
        : DerObjectIdentifier
    {
        private static readonly string IdQt = X509ObjectIdentifiers.IdPkix.Branch("2").GetID();

        private PolicyQualifierID(string id)
            : base(id)
        {
        }

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.2.1</c>.</summary>
        public static readonly PolicyQualifierID IdQtCps = new PolicyQualifierID(IdQt + ".1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.2.2</c>.</summary>
        public static readonly PolicyQualifierID IdQtUnotice = new PolicyQualifierID(IdQt + ".2");
    }
}
