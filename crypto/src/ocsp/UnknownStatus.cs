namespace Org.BouncyCastle.Ocsp
{
    /// <summary>
    /// The status of a certificate the responder knows nothing about, wrapping the UnknownInfo object.
    /// </summary>
    public class UnknownStatus
        : CertificateStatus
    {
        /// <summary>Create an unknown status.</summary>
        public UnknownStatus()
        {
        }
    }
}
