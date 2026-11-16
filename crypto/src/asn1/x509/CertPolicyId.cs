namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * CertPolicyId, used in the CertificatePolicies and PolicyMappings
     * X509V3 Extensions.
     *
     * <pre>
     *     CertPolicyId ::= OBJECT IDENTIFIER
     * </pre>
     */
    // TODO[api] Remove and just use DerObjectIdentifier
    public class CertPolicyID
        : DerObjectIdentifier
    {
        /// <summary>Create a new <see cref="CertPolicyID"/>.</summary>
        /// <param name="id">The id.</param>
        public CertPolicyID(string id)
            : base(id)
        {
        }
    }
}
