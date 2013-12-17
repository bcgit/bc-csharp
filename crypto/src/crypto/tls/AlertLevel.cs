namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>
    /// RFC 5246 7.2
    /// </summary>
    public abstract class AlertLevel
    {
        public const byte warning = 1;
        public const byte fatal = 2;
    }
}
