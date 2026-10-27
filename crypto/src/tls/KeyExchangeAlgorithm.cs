using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    public abstract class KeyExchangeAlgorithm
    {
        /*
         * NOTE: We interpret TLS 1.3 cipher suites as having a NULL key exchange
         */
        public const int NULL = 0;

        /// <summary>The <c>RSA</c> constant, with the value <c>1</c>.</summary>
        public const int RSA = 1;
        /// <summary>The <c>RSA_EXPORT</c> constant, with the value <c>2</c>.</summary>
        public const int RSA_EXPORT = 2;
        /// <summary>The <c>DHE_DSS</c> constant, with the value <c>3</c>.</summary>
        public const int DHE_DSS = 3;
        /// <summary>The <c>DHE_DSS_EXPORT</c> constant, with the value <c>4</c>.</summary>
        public const int DHE_DSS_EXPORT = 4;
        /// <summary>The <c>DHE_RSA</c> constant, with the value <c>5</c>.</summary>
        public const int DHE_RSA = 5;
        /// <summary>The <c>DHE_RSA_EXPORT</c> constant, with the value <c>6</c>.</summary>
        public const int DHE_RSA_EXPORT = 6;
        /// <summary>The <c>DH_DSS</c> constant, with the value <c>7</c>.</summary>
        public const int DH_DSS = 7;
        /// <summary>The <c>DH_DSS_EXPORT</c> constant, with the value <c>8</c>.</summary>
        public const int DH_DSS_EXPORT = 8;
        /// <summary>The <c>DH_RSA</c> constant, with the value <c>9</c>.</summary>
        public const int DH_RSA = 9;
        /// <summary>The <c>DH_RSA_EXPORT</c> constant, with the value <c>10</c>.</summary>
        public const int DH_RSA_EXPORT = 10;
        /// <summary>The <c>DH_anon</c> constant, with the value <c>11</c>.</summary>
        public const int DH_anon = 11;
        /// <summary>The <c>DH_anon_EXPORT</c> constant, with the value <c>12</c>.</summary>
        public const int DH_anon_EXPORT = 12;

        /*
         * RFC 4279
         */
        public const int PSK = 13;
        /// <summary>The <c>DHE_PSK</c> constant, with the value <c>14</c>.</summary>
        public const int DHE_PSK = 14;
        /// <summary>The <c>RSA_PSK</c> constant, with the value <c>15</c>.</summary>
        public const int RSA_PSK = 15;

        /*
         * RFC 4429
         */
        public const int ECDH_ECDSA = 16;
        /// <summary>The <c>ECDHE_ECDSA</c> constant, with the value <c>17</c>.</summary>
        public const int ECDHE_ECDSA = 17;
        /// <summary>The <c>ECDH_RSA</c> constant, with the value <c>18</c>.</summary>
        public const int ECDH_RSA = 18;
        /// <summary>The <c>ECDHE_RSA</c> constant, with the value <c>19</c>.</summary>
        public const int ECDHE_RSA = 19;
        /// <summary>The <c>ECDH_anon</c> constant, with the value <c>20</c>.</summary>
        public const int ECDH_anon = 20;

        /*
         * RFC 5054
         */
        public const int SRP = 21;
        /// <summary>The <c>SRP_DSS</c> constant, with the value <c>22</c>.</summary>
        public const int SRP_DSS = 22;
        /// <summary>The <c>SRP_RSA</c> constant, with the value <c>23</c>.</summary>
        public const int SRP_RSA = 23;

        /*
         * RFC 5489
         */
        public const int ECDHE_PSK = 24;

        /*
         * GMT 0024-2014
         */
        public const int SM2 = 25;

        /*
         * RFC 9189
         */
        public const int GOSTR341112_256 = 26;

        /// <summary>Determine whether a key exchange algorithm is an anonymous one.</summary>
        /// <param name="keyExchangeAlgorithm">The key exchange algorithm.</param>
        /// <returns>true if the key exchange is anonymous, false otherwise.</returns>
        public static bool IsAnonymous(int keyExchangeAlgorithm)
        {
            switch (keyExchangeAlgorithm)
            {
            case DH_anon:
            case DH_anon_EXPORT:
            case ECDH_anon:
                return true;
            default:
                return false;
            }
        }
    }
}
