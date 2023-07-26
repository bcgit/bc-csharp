using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Operators.Utilities
{
    /// <summary>
    /// Base interface for a finder of digest algorithm identifiers used with signatures.
    /// </summary>
    public interface IDigestAlgorithmFinder
    {
        /// <summary>
        /// Find the digest algorithm identifier that matches with the passed in signature algorithm identifier.
        /// </summary>
        /// <param name="signatureAlgorithm">the signature algorithm of interest.</param>
        /// <returns>an algorithm identifier for the corresponding digest.</returns>
        AlgorithmIdentifier Find(AlgorithmIdentifier signatureAlgorithm);

        /// <summary>
        /// Find the digest algorithm identifier that matches with the passed in digest name.
        /// </summary>
        /// <param name="digestOid">the OID of the digest algorithm of interest.</param>
        /// <returns>an algorithm identifier for the digest signature.</returns>
        AlgorithmIdentifier Find(DerObjectIdentifier digestOid);

        /// <summary>
        /// Find the digest algorithm identifier that matches with the passed in digest name.
        /// </summary>
        /// <param name="digestName">the name of the digest algorithm of interest.</param>
        /// <returns>an algorithm identifier for the digest signature.</returns>
        AlgorithmIdentifier Find(string digestName);
    }
}
