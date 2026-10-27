using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Base class for user-supplied checks that are applied to an attribute certificate.</summary>
    public abstract class PkixAttrCertChecker
    {
        /// <summary>
        /// Returns the X.509 attribute certificate extensions that this checker supports, or null if no extensions
        /// are supported.
        /// </summary>
        /// <remarks>
        /// All attribute certificate extensions that the checker might possibly be able to process should be
        /// included.
        /// </remarks>
        /// <returns>The supported extension OIDs, or null if no extensions are supported.</returns>
        public abstract ISet<DerObjectIdentifier> GetSupportedExtensions();

        /// <summary>Performs checks on the specified attribute certificate.</summary>
        /// <remarks>Every handled extension is removed from the <paramref name="unresolvedCritExts"/> collection.
        /// </remarks>
        /// <param name="attrCert">The attribute certificate to be checked.</param>
        /// <param name="certPath">
        /// The certificate path which belongs to the attribute certificate issuer public key certificate.
        /// </param>
        /// <param name="holderCertPath">The certificate path which belongs to the holder certificate.</param>
        /// <param name="unresolvedCritExts">
        /// The OID strings of the current set of unresolved critical extensions.
        /// </param>
        /// <exception cref="PkixCertPathValidatorException">The attribute certificate does not pass the check.
        /// </exception>
        public abstract void Check(X509V2AttributeCertificate attrCert, PkixCertPath certPath,
            PkixCertPath holderCertPath, ICollection<string> unresolvedCritExts);

        /// <summary>Returns a clone of this object.</summary>
        /// <returns>A copy of this checker.</returns>
        public abstract PkixAttrCertChecker Clone();
    }
}
