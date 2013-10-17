namespace Org.BouncyCastle.Crypto.Tls
{
    /**
     * RFC 2246
     * <p/>
     * Note that the values here are implementation-specific and arbitrary. It is recommended not to
     * depend on the particular values (e.g. serialization).
     */
    public enum MACAlgorithm : int
    {
        Null = 0,
        md5 = 1,
        sha = 2,
        /*
         * RFC 5246
         */
        hmac_md5 = md5,
        hmac_sha1 = sha,
        hmac_sha256 = 3,
        hmac_sha384 = 4,
        hmac_sha512 = 5,

        /*
         * TBD[draft-josefsson-salsa20-tls-02] 
         */
        umac96 = 100,
    }
}