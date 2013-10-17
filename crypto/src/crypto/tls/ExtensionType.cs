namespace Org.BouncyCastle.Crypto.Tls
{
	/// <summary>
	/// RFC 4366 2.3
	/// </summary>
    public enum ExtensionType : int
    {
        /*
        * RFC 2546 2.3.
        */
        server_name = 0,
        max_fragment_length = 1,
        client_certificate_url = 2,
        trusted_ca_keys = 3,
        truncated_hmac = 4,
        status_request = 5,

        /*
         * RFC 4681
         */
        user_mapping = 6,

        /*
         * RFC 4492 5.1.
         */
        elliptic_curves = 10,
        ec_point_formats = 11,

        /*
         * RFC 5054 2.8.1.
         */
        srp = 12,

        /*
         * RFC 5077 7.
         */
        session_ticket = 35,

        /*
         * RFC 5246 7.4.1.4.
         */
        signature_algorithms = 13,

        /*
         * RFC 5764 9.
         */
        use_srtp = 14,

        /*
         * RFC 6520 6.
         */
        heartbeat = 15,

        /*
         * RFC 5746 3.2.
         */
        renegotiation_info = 0xff01,
    }
}
