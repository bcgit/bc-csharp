using System;

namespace Org.BouncyCastle.Tls
{
    public abstract class HandshakeType
    {
        /*
         * RFC 2246 7.4
         */
        public const short hello_request = 0;
        /// <summary>The <c>client_hello</c> constant, with the value <c>1</c>.</summary>
        public const short client_hello = 1;
        /// <summary>The <c>server_hello</c> constant, with the value <c>2</c>.</summary>
        public const short server_hello = 2;
        /// <summary>The <c>certificate</c> constant, with the value <c>11</c>.</summary>
        public const short certificate = 11;
        /// <summary>The <c>server_key_exchange</c> constant, with the value <c>12</c>.</summary>
        public const short server_key_exchange = 12;
        /// <summary>The <c>certificate_request</c> constant, with the value <c>13</c>.</summary>
        public const short certificate_request = 13;
        /// <summary>The <c>server_hello_done</c> constant, with the value <c>14</c>.</summary>
        public const short server_hello_done = 14;
        /// <summary>The <c>certificate_verify</c> constant, with the value <c>15</c>.</summary>
        public const short certificate_verify = 15;
        /// <summary>The <c>client_key_exchange</c> constant, with the value <c>16</c>.</summary>
        public const short client_key_exchange = 16;
        /// <summary>The <c>finished</c> constant, with the value <c>20</c>.</summary>
        public const short finished = 20;

        /*
         * RFC 3546 2.4
         */
        public const short certificate_url = 21;
        /// <summary>The <c>certificate_status</c> constant, with the value <c>22</c>.</summary>
        public const short certificate_status = 22;

        /*
         * (DTLS) RFC 4347 4.3.2
         */
        public const short hello_verify_request = 3;

        /*
         * RFC 4680
         */
        public const short supplemental_data = 23;

        /*
         * RFC 8446
         */
        public const short new_session_ticket = 4;
        /// <summary>The <c>end_of_early_data</c> constant, with the value <c>5</c>.</summary>
        public const short end_of_early_data = 5;
        /// <summary>The <c>hello_retry_request</c> constant, with the value <c>6</c>.</summary>
        public const short hello_retry_request = 6;
        /// <summary>The <c>encrypted_extensions</c> constant, with the value <c>8</c>.</summary>
        public const short encrypted_extensions = 8;
        /// <summary>The <c>key_update</c> constant, with the value <c>24</c>.</summary>
        public const short key_update = 24;
        /// <summary>The <c>message_hash</c> constant, with the value <c>254</c>.</summary>
        public const short message_hash = 254;

        /*
         * RFC 8870
         */
        public const short ekt_key = 26;

        /*
         * RFC 8879
         */
        public const short compressed_certificate = 25;

        /*
         * RFC 9147
         */
        public const short request_connection_id = 9;
        /// <summary>The <c>new_connection_id</c> constant, with the value <c>10</c>.</summary>
        public const short new_connection_id = 10;

        /*
         * RFC 9261
         */
        public const short client_certificate_request = 17;

        public static string GetName(short handshakeType)
        {
            switch (handshakeType)
            {
            case hello_request:
                return "hello_request";
            case client_hello:
                return "client_hello";
            case server_hello:
                return "server_hello";
            case certificate:
                return "certificate";
            case server_key_exchange:
                return "server_key_exchange";
            case certificate_request:
                return "certificate_request";
            case server_hello_done:
                return "server_hello_done";
            case certificate_verify:
                return "certificate_verify";
            case client_key_exchange:
                return "client_key_exchange";
            case finished:
                return "finished";
            case certificate_url:
                return "certificate_url";
            case certificate_status:
                return "certificate_status";
            case hello_verify_request:
                return "hello_verify_request";
            case supplemental_data:
                return "supplemental_data";
            case new_session_ticket:
                return "new_session_ticket";
            case end_of_early_data:
                return "end_of_early_data";
            case hello_retry_request:
                return "hello_retry_request";
            case encrypted_extensions:
                return "encrypted_extensions";
            case key_update:
                return "key_update";
            case message_hash:
                return "message_hash";
            case ekt_key:
                return "ekt_key";
            case compressed_certificate:
                return "compressed_certificate";
            case request_connection_id:
                return "request_connection_id";
            case new_connection_id:
                return "new_connection_id";
            case client_certificate_request:
                return "client_certificate_request";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(short handshakeType)
        {
            return GetName(handshakeType) + "(" + handshakeType + ")";
        }

        public static bool IsRecognized(short handshakeType)
        {
            switch (handshakeType)
            {
            case hello_request:
            case client_hello:
            case server_hello:
            case certificate:
            case server_key_exchange:
            case certificate_request:
            case server_hello_done:
            case certificate_verify:
            case client_key_exchange:
            case finished:
            case certificate_url:
            case certificate_status:
            case hello_verify_request:
            case supplemental_data:
            case new_session_ticket:
            case end_of_early_data:
            case hello_retry_request:
            case encrypted_extensions:
            case key_update:
            case message_hash:
            case ekt_key:
            case compressed_certificate:
            case request_connection_id:
            case new_connection_id:
            case client_certificate_request:
                return true;
            default:
                return false;
            }
        }
    }
}
