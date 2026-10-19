using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    public abstract class CryptoHashAlgorithm
    {
        /// <summary>The <c>md5</c> constant, with the value <c>1</c>.</summary>
        public const int md5 = 1;
        /// <summary>The <c>sha1</c> constant, with the value <c>2</c>.</summary>
        public const int sha1 = 2;
        /// <summary>The <c>sha224</c> constant, with the value <c>3</c>.</summary>
        public const int sha224 = 3;
        /// <summary>The <c>sha256</c> constant, with the value <c>4</c>.</summary>
        public const int sha256 = 4;
        /// <summary>The <c>sha384</c> constant, with the value <c>5</c>.</summary>
        public const int sha384 = 5;
        /// <summary>The <c>sha512</c> constant, with the value <c>6</c>.</summary>
        public const int sha512 = 6;
        /// <summary>The <c>sm3</c> constant, with the value <c>7</c>.</summary>
        public const int sm3 = 7;
        /// <summary>The <c>gostr3411_2012_256</c> constant, with the value <c>8</c>.</summary>
        public const int gostr3411_2012_256 = 8;
    }
}
