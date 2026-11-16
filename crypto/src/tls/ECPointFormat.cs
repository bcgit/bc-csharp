using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 4492 5.1.2</summary>
    public abstract class ECPointFormat
    {
        /// <summary>The <c>uncompressed</c> constant, with the value <c>0</c>.</summary>
        public const short uncompressed = 0;
        /// <summary>The <c>ansiX962_compressed_prime</c> constant, with the value <c>1</c>.</summary>
        public const short ansiX962_compressed_prime = 1;
        /// <summary>The <c>ansiX962_compressed_char2</c> constant, with the value <c>2</c>.</summary>
        public const short ansiX962_compressed_char2 = 2;

        /*
         * reserved (248..255)
         */
    }
}
