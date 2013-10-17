namespace Org.BouncyCastle.Crypto.Tls
{
    public enum ClientAuthenticationType : short
    {
        /*
         * RFC 5077 4
         */
        anonymous = 0,
        certificate_based = 1,
        psk = 2,
    }

}