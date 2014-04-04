using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    /**
     * RFC 5705
     */
    public class ExporterLabel
    {
        /*
         * BC-specific
         */
        internal const string client_random = "client random";
        internal const string server_random = "server random";

        /*
         * RFC 5246
         */
        public const string client_finished = "client finished";
        public const string server_finished = "server finished";
        public const string master_secret = "master secret";
        public const string key_expansion = "key expansion";

        /*
         * RFC 5216
         */
        public const string client_EAP_encryption = "client EAP encryption";

        /*
         * RFC 5281
         */
        public const string ttls_keying_material = "ttls keying material";
        public const string ttls_challenge = "ttls challenge";

        /*
         * RFC 5764
         */
        public const string dtls_srtp = "EXTRACTOR-dtls_srtp";
    }
}
