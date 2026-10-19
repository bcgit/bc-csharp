namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Interface for the domain of a key encapsulation mechanism (KEM) in TLS.</summary>
    public interface TlsKemDomain
    {
        TlsAgreement CreateKem();
    }
}
