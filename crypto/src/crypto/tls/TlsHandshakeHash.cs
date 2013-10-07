namespace Org.BouncyCastle.Crypto.Tls
{
    interface TlsHandshakeHash : IDigest
    {
        void Init(TlsContext context);

        TlsHandshakeHash Commit();

        TlsHandshakeHash Fork();
    }
}