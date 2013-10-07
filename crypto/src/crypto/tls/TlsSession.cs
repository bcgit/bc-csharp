namespace Org.BouncyCastle.Crypto.Tls
{
    public interface TlsSession
    {
        SessionParameters ExportSessionParameters();

        byte[] GetSessionID();

        void Invalidate();

        bool IsResumable
        {
            get;
        }
    }
}