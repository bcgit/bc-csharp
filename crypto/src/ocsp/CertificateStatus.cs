namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Base class for the non-good certificate statuses reported in an OCSP response.</summary>
    /// <seealso cref="RevokedStatus"/>
    /// <seealso cref="UnknownStatus"/>
    public abstract class CertificateStatus
    {
        /// <summary>The status of a certificate that is good, which is represented by null.</summary>
        public static readonly CertificateStatus Good = null;
    }
}
