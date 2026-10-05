namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// The reason a <see cref="PkixCertPathValidatorException"/> was thrown, as reported by its
    /// <see cref="PkixCertPathValidatorException.Reason"/> property.
    /// </summary>
    /// <remarks>
    /// Most values correspond to failures of the RFC 5280 path validation algorithm. The exceptions,
    /// <see cref="AlgorithmConstrained"/> and <see cref="LimitExceeded"/>, reflect local policy or configuration, and
    /// the path may otherwise be valid.
    /// <para>
    /// Further values may be added in future releases, so consumers should treat unrecognized values as
    /// <see cref="Unspecified"/>.
    /// </para>
    /// </remarks>
    public enum PkixCertPathValidatorReason
    {
        /// <summary>Unspecified reason.</summary>
        Unspecified = 0,
        /// <summary>The certificate is expired.</summary>
        Expired = 1,
        /// <summary>The certificate is not yet valid.</summary>
        NotYetValid = 2,
        /// <summary>The certificate is revoked.</summary>
        Revoked = 3,
        /// <summary>The revocation status of the certificate could not be determined.</summary>
        UndeterminedRevocationStatus = 4,
        /// <summary>The signature is invalid.</summary>
        InvalidSignature = 5,
        /// <summary>
        /// The signature algorithm, public key, or public key parameters are disallowed by local policy (e.g. a weak
        /// algorithm or an insufficient key size).
        /// </summary>
        /// <remarks>Not intended for algorithms that are simply unsupported.</remarks>
        AlgorithmConstrained = 6,
        /// <summary>The certificate does not chain correctly.</summary>
        NameChaining = 7,
        /// <summary>The certificate's key usage is invalid.</summary>
        InvalidKeyUsage = 8,
        /// <summary>
        /// Certificate policy validation failed, or a critical policy extension could not be processed.
        /// </summary>
        InvalidPolicy = 9,
        /// <summary>No acceptable trust anchor found.</summary>
        NoTrustAnchor = 10,
        /// <summary>The certificate contains one or more unrecognized critical extensions.</summary>
        /// <remarks>
        /// A recognized critical extension that cannot be processed is instead reported under the reason for its
        /// area, e.g. <see cref="InvalidName"/> or <see cref="InvalidPolicy"/>.
        /// </remarks>
        UnrecognizedCriticalExtension = 11,
        /// <summary>The certificate is not a CA certificate.</summary>
        NotCACertificate = 12,
        /// <summary>The path length constraint has been violated.</summary>
        PathTooLong = 13,
        /// <summary>The name constraints have been violated, or could not be processed.</summary>
        InvalidName = 14,
        /// <summary>A processing limit was exceeded (e.g. the maximum number of policy tree nodes).</summary>
        /// <remarks>
        /// Reflects local configuration rather than an RFC 5280 failure, and the path may otherwise be valid. The
        /// exception message identifies the limit.
        /// </remarks>
        LimitExceeded = 15,
    }
}
