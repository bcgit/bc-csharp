using System;

namespace Org.BouncyCastle.Tls
{
    public abstract class ExtensionType
    {
        /*
         * RFC 2546 2.3.
         */
        public const int server_name = 0;
        /// <summary>The <c>max_fragment_length</c> constant, with the value <c>1</c>.</summary>
        public const int max_fragment_length = 1;
        /// <summary>The <c>client_certificate_url</c> constant, with the value <c>2</c>.</summary>
        public const int client_certificate_url = 2;
        /// <summary>The <c>trusted_ca_keys</c> constant, with the value <c>3</c>.</summary>
        public const int trusted_ca_keys = 3;
        /// <summary>The <c>truncated_hmac</c> constant, with the value <c>4</c>.</summary>
        public const int truncated_hmac = 4;
        /// <summary>The <c>status_request</c> constant, with the value <c>5</c>.</summary>
        public const int status_request = 5;

        /*
         * RFC 4681
         */
        public const int user_mapping = 6;

        /*
         * RFC 5878
         */
        public const int client_authz = 7;
        /// <summary>The <c>server_authz</c> constant, with the value <c>8</c>.</summary>
        public const int server_authz = 8;

        /*
         * RFC 6091
         */
        public const int cert_type = 9;

        /*
         * RFC 7919 (originally 'elliptic_curves' from RFC 4492)
         */
        public const int supported_groups = 10;

        /*
         * RFC 4492 5.1.
         */
        public const int ec_point_formats = 11;

        /*
         * RFC 5054 2.8.1.
         */
        public const int srp = 12;

        /*
         * RFC 5246 7.4.1.4.
         */
        public const int signature_algorithms = 13;

        /*
         * RFC 5764 9.
         */
        public const int use_srtp = 14;

        /*
         * RFC 6520 6.
         */
        public const int heartbeat = 15;

        /*
         * RFC 7301
         */
        public const int application_layer_protocol_negotiation = 16;

        /*
         * RFC 6961
         */
        public const int status_request_v2 = 17;

        /*
         * RFC 6962
         */
        public const int signed_certificate_timestamp = 18;

        /*
         * RFC 7250
         */
        public const int client_certificate_type = 19;
        /// <summary>The <c>server_certificate_type</c> constant, with the value <c>20</c>.</summary>
        public const int server_certificate_type = 20;

        /*
         * RFC 7685
         */
        public const int padding = 21;

        /*
         * RFC 7366
         */
        public const int encrypt_then_mac = 22;

        /*
         * RFC 7627
         */
        public const int extended_master_secret = 23;

        /*
         * RFC 8472
         */
        public const int token_binding = 24;

        /*
         * RFC 7924
         */
        public const int cached_info = 25;

        /*
         * RFC 8879
         */
        public const int compress_certificate = 27;

        /*
         * RFC 8449
         */
        public const int record_size_limit = 28;

        /*
         * RFC 5077 7.
         */
        public const int session_ticket = 35;

        /*
         * RFC 8446
         */
        public const int pre_shared_key = 41;
        /// <summary>The <c>early_data</c> constant, with the value <c>42</c>.</summary>
        public const int early_data = 42;
        /// <summary>The <c>supported_versions</c> constant, with the value <c>43</c>.</summary>
        public const int supported_versions = 43;
        /// <summary>The <c>cookie</c> constant, with the value <c>44</c>.</summary>
        public const int cookie = 44;
        /// <summary>The <c>psk_key_exchange_modes</c> constant, with the value <c>45</c>.</summary>
        public const int psk_key_exchange_modes = 45;
        /// <summary>The <c>certificate_authorities</c> constant, with the value <c>47</c>.</summary>
        public const int certificate_authorities = 47;
        /// <summary>The <c>oid_filters</c> constant, with the value <c>48</c>.</summary>
        public const int oid_filters = 48;
        /// <summary>The <c>post_handshake_auth</c> constant, with the value <c>49</c>.</summary>
        public const int post_handshake_auth = 49;
        /// <summary>The <c>signature_algorithms_cert</c> constant, with the value <c>50</c>.</summary>
        public const int signature_algorithms_cert = 50;
        /// <summary>The <c>key_share</c> constant, with the value <c>51</c>.</summary>
        public const int key_share = 51;

        /*
         * RFC 9146
         */
        public const int connection_id = 54;

        /*
         * RFC 5746 3.2.
         */
        public const int renegotiation_info = 0xff01;

        public static string GetName(int extensionType)
        {
            switch (extensionType)
            {
            case server_name:
                return "server_name";
            case max_fragment_length:
                return "max_fragment_length";
            case client_certificate_url:
                return "client_certificate_url";
            case trusted_ca_keys:
                return "trusted_ca_keys";
            case truncated_hmac:
                return "truncated_hmac";
            case status_request:
                return "status_request";
            case user_mapping:
                return "user_mapping";
            case client_authz:
                return "client_authz";
            case server_authz:
                return "server_authz";
            case cert_type:
                return "cert_type";
            case supported_groups:
                return "supported_groups";
            case ec_point_formats:
                return "ec_point_formats";
            case srp:
                return "srp";
            case signature_algorithms:
                return "signature_algorithms";
            case use_srtp:
                return "use_srtp";
            case heartbeat:
                return "heartbeat";
            case application_layer_protocol_negotiation:
                return "application_layer_protocol_negotiation";
            case status_request_v2:
                return "status_request_v2";
            case signed_certificate_timestamp:
                return "signed_certificate_timestamp";
            case client_certificate_type:
                return "client_certificate_type";
            case server_certificate_type:
                return "server_certificate_type";
            case padding:
                return "padding";
            case encrypt_then_mac:
                return "encrypt_then_mac";
            case extended_master_secret:
                return "extended_master_secret";
            case token_binding:
                return "token_binding";
            case cached_info:
                return "cached_info";
            case compress_certificate:
                return "compress_certificate";
            case record_size_limit:
                return "record_size_limit";
            case session_ticket:
                return "session_ticket";
            case pre_shared_key:
                return "pre_shared_key";
            case early_data:
                return "early_data";
            case supported_versions:
                return "supported_versions";
            case cookie:
                return "cookie";
            case psk_key_exchange_modes:
                return "psk_key_exchange_modes";
            case certificate_authorities:
                return "certificate_authorities";
            case oid_filters:
                return "oid_filters";
            case post_handshake_auth:
                return "post_handshake_auth";
            case signature_algorithms_cert:
                return "signature_algorithms_cert";
            case key_share:
                return "key_share";
            case connection_id:
                return "connection_id";
            case renegotiation_info:
                return "renegotiation_info";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(int extensionType)
        {
            return GetName(extensionType) + "(" + extensionType + ")";
        }

        public static bool IsRecognized(int extensionType)
        {
            switch (extensionType)
            {
            case server_name:
            case max_fragment_length:
            case client_certificate_url:
            case trusted_ca_keys:
            case truncated_hmac:
            case status_request:
            case user_mapping:
            case client_authz:
            case server_authz:
            case cert_type:
            case supported_groups:
            case ec_point_formats:
            case srp:
            case signature_algorithms:
            case use_srtp:
            case heartbeat:
            case application_layer_protocol_negotiation:
            case status_request_v2:
            case signed_certificate_timestamp:
            case client_certificate_type:
            case server_certificate_type:
            case padding:
            case encrypt_then_mac:
            case extended_master_secret:
            case token_binding:
            case cached_info:
            case compress_certificate:
            case record_size_limit:
            case session_ticket:
            case pre_shared_key:
            case early_data:
            case supported_versions:
            case cookie:
            case psk_key_exchange_modes:
            case certificate_authorities:
            case oid_filters:
            case post_handshake_auth:
            case signature_algorithms_cert:
            case key_share:
            case connection_id:
            case renegotiation_info:

            /*
             * WARNING: When adding a new "recognized" extension type, also register with
             * TlsUtilities.IsPermittedExtensionType13 the TLS 1.3 messages it may appear in (if any). A recognized
             * type not registered there is rejected with illegal_parameter in any TLS 1.3 message that is checked.
             */

                return true;
            default:
                return false;
            }
        }
    }
}
