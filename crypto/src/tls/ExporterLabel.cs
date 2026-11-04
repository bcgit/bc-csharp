using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 5705</summary>
    public abstract class ExporterLabel
    {
        /*
         * RFC 5246
         */
        public const string client_finished = "client finished";
        /// <summary>The <c>server_finished</c> constant, with the value <c>server finished</c>.</summary>
        public const string server_finished = "server finished";
        /// <summary>The <c>master_secret</c> constant, with the value <c>master secret</c>.</summary>
        public const string master_secret = "master secret";
        /// <summary>The <c>key_expansion</c> constant, with the value <c>key expansion</c>.</summary>
        public const string key_expansion = "key expansion";

        /*
         * RFC 5216
         */
        public const string client_EAP_encryption = "client EAP encryption";

        /*
         * RFC 5281
         */
        public const string ttls_keying_material = "ttls keying material";
        /// <summary>The <c>ttls_challenge</c> constant, with the value <c>ttls challenge</c>.</summary>
        public const string ttls_challenge = "ttls challenge";

        /*
         * RFC 5764
         */
        public const string dtls_srtp = "EXTRACTOR-dtls_srtp";

        /*
         * RFC 7627
         */
        public const string extended_master_secret = "extended master secret";

        /*
         * draft-ietf-tokbind-protocol-16
         */
        public const string token_binding = "EXPORTER-Token-Binding";
    }
}
