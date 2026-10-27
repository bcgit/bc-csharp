using System.Collections.Generic;

using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Base class for user-supplied checks that are applied to each certificate of a path.</summary>
    /// <remarks>
    /// A checker is added to <see cref="PkixParameters"/> and is then called for every certificate during
    /// validation, which allows application-specific checks and the processing of critical extensions that the
    /// validator itself does not recognise.
    /// </remarks>
    public abstract class PkixCertPathChecker
    {
        /// <summary>Default constructor for subclasses.</summary>
        protected PkixCertPathChecker()
        {
        }

        /// <summary>Initializes the internal state of this <c>PkixCertPathChecker</c>.</summary>
        /// <remarks>
        /// The <paramref name="forward"/> flag specifies the order that certificates will be passed to the
        /// <see cref="Check"/> method (forward or reverse). A checker must support reverse checking and may support
        /// forward checking.
        /// </remarks>
        /// <param name="forward">
        /// The order that certificates are presented to <see cref="Check"/>. If true, certificates are presented from
        /// target to most-trusted CA (forward); if false, from most-trusted CA to target (reverse).
        /// </param>
        /// <exception cref="PkixCertPathValidatorException">
        /// The checker is unable to check certificates in the specified order; it should never be thrown if
        /// <paramref name="forward"/> is false since reverse checking must be supported.
        /// </exception>
        public abstract void Init(bool forward);

        /// <summary>Indicates if forward checking is supported.</summary>
        /// <remarks>
        /// Forward checking refers to the ability of the checker to perform its checks when certificates are presented
        /// to <see cref="Check"/> in the forward direction (from target to most-trusted CA).
        /// </remarks>
        /// <returns>true if forward checking is supported, false otherwise.</returns>
        public abstract bool IsForwardCheckingSupported();

        /// <summary>
        /// Returns the X.509 certificate extensions that this checker supports (i.e. recognizes and is able to
        /// process), or null if no extensions are supported.
        /// </summary>
        /// <remarks>
        /// Each element of the set is a string holding the object identifier of a supported extension, in
        /// dotted-decimal form. All extensions that the checker might possibly be able to process should be included.
        /// </remarks>
        /// <returns>The supported extension OIDs, or null if no extensions are supported.</returns>
        public abstract ISet<string> GetSupportedExtensions();

        /// <summary>
        /// Performs the check(s) on the specified certificate using its internal state and removes any critical
        /// extensions that it processes from the specified collection of unresolved critical extensions.
        /// </summary>
        /// <remarks>The certificates are presented in the order specified by <see cref="Init"/>.</remarks>
        /// <param name="cert">The certificate to be checked.</param>
        /// <param name="unresolvedCritExts">
        /// The OID strings of the current set of unresolved critical extensions.
        /// </param>
        /// <exception cref="PkixCertPathValidatorException">The certificate does not pass the check.</exception>
        public abstract void Check(X509Certificate cert, ISet<string> unresolvedCritExts);

        /// <summary>Returns a clone of this object.</summary>
        /// <remarks>All subclasses which maintain state must support and override this method, if necessary.</remarks>
        /// <returns>A copy of this checker.</returns>
        public virtual object Clone()
        {
            // TODO Check this
            return base.MemberwiseClone();
        }
    }
}
