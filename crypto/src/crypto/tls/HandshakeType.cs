namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>
    /// RFC 2246 7.4
    /// </summary>
    public enum HandshakeType : byte
    {
        /*
         * RFC 2246 7.4
         */
        hello_request = 0,
        client_hello = 1,
        server_hello = 2,
        certificate = 11,
        server_key_exchange = 12,
        certificate_request = 13,
        server_hello_done = 14,
        certificate_verify = 15,
        client_key_exchange = 16,
        finished = 20,

        /*
         * RFC 3546 2.4
         */
        certificate_url = 21,
        certificate_status = 22,

        /*
         *  (DTLS) RFC 4347 4.3.2
         */
        hello_verify_request = 3,

        /*
         * RFC 4680 
         */
        supplemental_data = 23,

        /*
         * RFC 5077 
         */
        session_ticket = 4,
    }
}
