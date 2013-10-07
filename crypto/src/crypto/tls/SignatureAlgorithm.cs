namespace Org.BouncyCastle.Crypto.Tls
{
    /**
     * RFC 5246 7.4.1.4.1 (in RFC 2246, there were no specific values assigned)
     */
    public static class SignatureAlgorithm
    {
        public const short anonymous = 0;
        public const short rsa = 1;
        public const short dsa = 2;
        public const short ecdsa = 3;
    }
}