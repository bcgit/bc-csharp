namespace Org.BouncyCastle.Tls.Crypto
{
    public interface TlsKemDomain
    {
        TlsAgreement CreateKem();
    }
}
