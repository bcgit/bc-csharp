namespace Org.BouncyCastle.Crypto.Tls
{

    /**
     * RFC 2246
     * <p/>
     * Note that the values here are implementation-specific and arbitrary. It is recommended not to
     * depend on the particular values (e.g. serialization).
     */
    public class ConnectionEnd
    {

        public const int server = 0;
        public const int client = 1;
    }
}