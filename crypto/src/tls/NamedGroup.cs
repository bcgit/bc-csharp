using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 7919</summary>
    // TODO[api] Make static
    public abstract class NamedGroup
    {
        /*
         * RFC 4492 5.1.1
         * <p>
         * The named curves defined here are those specified in SEC 2 [13]. Note that many of these curves
         * are also recommended in ANSI X9.62 [7] and FIPS 186-2 [11]. Values 0xFE00 through 0xFEFF are
         * reserved for private use. Values 0xFF01 and 0xFF02 indicate that the client supports arbitrary
         * prime and characteristic-2 curves, respectively (the curve parameters must be encoded explicitly
         * in ECParameters).
         */
        public const int sect163k1 = 1;
        /// <summary>The <c>sect163r1</c> constant, with the value <c>2</c>.</summary>
        public const int sect163r1 = 2;
        /// <summary>The <c>sect163r2</c> constant, with the value <c>3</c>.</summary>
        public const int sect163r2 = 3;
        /// <summary>The <c>sect193r1</c> constant, with the value <c>4</c>.</summary>
        public const int sect193r1 = 4;
        /// <summary>The <c>sect193r2</c> constant, with the value <c>5</c>.</summary>
        public const int sect193r2 = 5;
        /// <summary>The <c>sect233k1</c> constant, with the value <c>6</c>.</summary>
        public const int sect233k1 = 6;
        /// <summary>The <c>sect233r1</c> constant, with the value <c>7</c>.</summary>
        public const int sect233r1 = 7;
        /// <summary>The <c>sect239k1</c> constant, with the value <c>8</c>.</summary>
        public const int sect239k1 = 8;
        /// <summary>The <c>sect283k1</c> constant, with the value <c>9</c>.</summary>
        public const int sect283k1 = 9;
        /// <summary>The <c>sect283r1</c> constant, with the value <c>10</c>.</summary>
        public const int sect283r1 = 10;
        /// <summary>The <c>sect409k1</c> constant, with the value <c>11</c>.</summary>
        public const int sect409k1 = 11;
        /// <summary>The <c>sect409r1</c> constant, with the value <c>12</c>.</summary>
        public const int sect409r1 = 12;
        /// <summary>The <c>sect571k1</c> constant, with the value <c>13</c>.</summary>
        public const int sect571k1 = 13;
        /// <summary>The <c>sect571r1</c> constant, with the value <c>14</c>.</summary>
        public const int sect571r1 = 14;
        /// <summary>The <c>secp160k1</c> constant, with the value <c>15</c>.</summary>
        public const int secp160k1 = 15;
        /// <summary>The <c>secp160r1</c> constant, with the value <c>16</c>.</summary>
        public const int secp160r1 = 16;
        /// <summary>The <c>secp160r2</c> constant, with the value <c>17</c>.</summary>
        public const int secp160r2 = 17;
        /// <summary>The <c>secp192k1</c> constant, with the value <c>18</c>.</summary>
        public const int secp192k1 = 18;
        /// <summary>The <c>secp192r1</c> constant, with the value <c>19</c>.</summary>
        public const int secp192r1 = 19;
        /// <summary>The <c>secp224k1</c> constant, with the value <c>20</c>.</summary>
        public const int secp224k1 = 20;
        /// <summary>The <c>secp224r1</c> constant, with the value <c>21</c>.</summary>
        public const int secp224r1 = 21;
        /// <summary>The <c>secp256k1</c> constant, with the value <c>22</c>.</summary>
        public const int secp256k1 = 22;
        /// <summary>The <c>secp256r1</c> constant, with the value <c>23</c>.</summary>
        public const int secp256r1 = 23;
        /// <summary>The <c>secp384r1</c> constant, with the value <c>24</c>.</summary>
        public const int secp384r1 = 24;
        /// <summary>The <c>secp521r1</c> constant, with the value <c>25</c>.</summary>
        public const int secp521r1 = 25;

        /*
         * RFC 7027
         */
        public const int brainpoolP256r1 = 26;
        /// <summary>The <c>brainpoolP384r1</c> constant, with the value <c>27</c>.</summary>
        public const int brainpoolP384r1 = 27;
        /// <summary>The <c>brainpoolP512r1</c> constant, with the value <c>28</c>.</summary>
        public const int brainpoolP512r1 = 28;

        /*
         * RFC 8422
         */
        public const int x25519 = 29;
        /// <summary>The <c>x448</c> constant, with the value <c>30</c>.</summary>
        public const int x448 = 30;

        /*
         * RFC 8734
         */
        public const int brainpoolP256r1tls13 = 31;
        /// <summary>The <c>brainpoolP384r1tls13</c> constant, with the value <c>32</c>.</summary>
        public const int brainpoolP384r1tls13 = 32;
        /// <summary>The <c>brainpoolP512r1tls13</c> constant, with the value <c>33</c>.</summary>
        public const int brainpoolP512r1tls13 = 33;

        /*
         * RFC 9189
         */
        public const int GC256A = 34;
        /// <summary>The <c>GC256B</c> constant, with the value <c>35</c>.</summary>
        public const int GC256B = 35;
        /// <summary>The <c>GC256C</c> constant, with the value <c>36</c>.</summary>
        public const int GC256C = 36;
        /// <summary>The <c>GC256D</c> constant, with the value <c>37</c>.</summary>
        public const int GC256D = 37;
        /// <summary>The <c>GC512A</c> constant, with the value <c>38</c>.</summary>
        public const int GC512A = 38;
        /// <summary>The <c>GC512B</c> constant, with the value <c>39</c>.</summary>
        public const int GC512B = 39;
        /// <summary>The <c>GC512C</c> constant, with the value <c>40</c>.</summary>
        public const int GC512C = 40;

        /*
         * RFC 8998
         */
        public const int curveSM2 = 41;

        /*
         * RFC 7919 2. Codepoints in the "Supported Groups Registry" with a high byte of 0x01 (that is,
         * between 256 and 511, inclusive) are set aside for FFDHE groups, though only a small number of
         * them are initially defined and we do not expect many other FFDHE groups to be added to this
         * range. No codepoints outside of this range will be allocated to FFDHE groups.
         */
        public const int ffdhe2048 = 256;
        /// <summary>The <c>ffdhe3072</c> constant, with the value <c>257</c>.</summary>
        public const int ffdhe3072 = 257;
        /// <summary>The <c>ffdhe4096</c> constant, with the value <c>258</c>.</summary>
        public const int ffdhe4096 = 258;
        /// <summary>The <c>ffdhe6144</c> constant, with the value <c>259</c>.</summary>
        public const int ffdhe6144 = 259;
        /// <summary>The <c>ffdhe8192</c> constant, with the value <c>260</c>.</summary>
        public const int ffdhe8192 = 260;

        /*
         * RFC 8446 reserved ffdhe_private_use (0x01FC..0x01FF)
         */

        /*
         * RFC 4492 reserved ecdhe_private_use (0xFE00..0xFEFF)
         */

        /*
         * RFC 4492
         */
        public const int arbitrary_explicit_prime_curves = 0xFF01;
        /// <summary>The <c>arbitrary_explicit_char2_curves</c> constant, with the value <c>0xFF02</c>.</summary>
        public const int arbitrary_explicit_char2_curves = 0xFF02;

        /*
         * draft-connolly-tls-mlkem-key-agreement-05
         */
        public const int MLKEM512 = 0x0200;
        /// <summary>The <c>MLKEM768</c> constant, with the value <c>0x0201</c>.</summary>
        public const int MLKEM768 = 0x0201;
        /// <summary>The <c>MLKEM1024</c> constant, with the value <c>0x0202</c>.</summary>
        public const int MLKEM1024 = 0x0202;

        /*
         * draft-ietf-tls-ecdhe-mlkem-00
         */
        public const int SecP256r1MLKEM768 = 0x11EB;
        /// <summary>The <c>X25519MLKEM768</c> constant, with the value <c>0x11EC</c>.</summary>
        public const int X25519MLKEM768 = 0x11EC;
        /// <summary>The <c>SecP384r1MLKEM1024</c> constant, with the value <c>0x11ED</c>.</summary>
        public const int SecP384r1MLKEM1024 = 0x11ED;

        /*
         * draft-yang-tls-hybrid-sm2-mlkem-03
         */
        public const int curveSM2MLKEM768 = 0x11EE;

        /* Names of the actual underlying elliptic curves (not necessarily matching the NamedGroup names). */
        private static readonly string[] CurveNames = new string[]{ "sect163k1", "sect163r1", "sect163r2", "sect193r1",
            "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
            "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
            "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1",
            "brainpoolP512r1", "X25519", "X448", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
            "Tc26-Gost-3410-12-256-paramSetA", "GostR3410-2001-CryptoPro-A", "GostR3410-2001-CryptoPro-B",
            "GostR3410-2001-CryptoPro-C", "Tc26-Gost-3410-12-512-paramSetA", "Tc26-Gost-3410-12-512-paramSetB",
            "Tc26-Gost-3410-12-512-paramSetC", "sm2p256v1" };

        private static readonly string[] FiniteFieldNames = new string[]{ "ffdhe2048", "ffdhe3072", "ffdhe4096",
            "ffdhe6144", "ffdhe8192" };

        public static bool CanBeNegotiated(int namedGroup, ProtocolVersion version)
        {
            switch (namedGroup)
            {
            case secp256r1:
            case secp384r1:
            case secp521r1:
            case x25519:
            case x448:
                return true;
            }

            if (RefersToASpecificFiniteField(namedGroup))
                return true;

            bool isTlsV13 = TlsUtilities.IsTlsV13(version);

            // NOTE: Version-independent curves checked above
            if (RefersToASpecificCurve(namedGroup))
            {
                switch (namedGroup)
                {
                case brainpoolP256r1tls13:
                case brainpoolP384r1tls13:
                case brainpoolP512r1tls13:
                case curveSM2:
                    return isTlsV13;
                default:
                    return !isTlsV13;
                }
            }

            if (RefersToASpecificHybrid(namedGroup) || RefersToASpecificKem(namedGroup))
                return isTlsV13;

            if (namedGroup >= arbitrary_explicit_prime_curves && namedGroup <= arbitrary_explicit_char2_curves)
                return !isTlsV13;

            return IsPrivate(namedGroup);
        }

        public static int GetCurveBits(int namedGroup)
        {
            switch (namedGroup)
            {
            case secp160k1:
            case secp160r1:
            case secp160r2:
                return 160;

            case sect163k1:
            case sect163r1:
            case sect163r2:
                return 163;

            case secp192k1:
            case secp192r1:
                return 192;

            case sect193r1:
            case sect193r2:
                return 193;

            case secp224k1:
            case secp224r1:
                return 224;

            case sect233k1:
            case sect233r1:
                return 233;

            case sect239k1:
                return 239;

            case x25519:
                return 252;

            case brainpoolP256r1:
            case brainpoolP256r1tls13:
            case curveSM2:
            case GC256A:
            case GC256B:
            case GC256C:
            case GC256D:
            case secp256k1:
            case secp256r1:
                return 256;

            case sect283k1:
            case sect283r1:
                return 283;

            case brainpoolP384r1:
            case brainpoolP384r1tls13:
            case secp384r1:
                return 384;

            case sect409k1:
            case sect409r1:
                return 409;

            case x448:
                return 446;

            case brainpoolP512r1:
            case brainpoolP512r1tls13:
            case GC512A:
            case GC512B:
            case GC512C:
                return 512;

            case secp521r1:
                return 521;

            case sect571k1:
            case sect571r1:
                return 571;

            default:
                return 0;
            }
        }

        public static string GetCurveName(int namedGroup)
        {
            if (RefersToASpecificCurve(namedGroup))
                return CurveNames[namedGroup - sect163k1];

            return null;
        }

        public static int GetFiniteFieldBits(int namedGroup)
        {
            switch (namedGroup)
            {
            case ffdhe2048:
                return 2048;
            case ffdhe3072:
                return 3072;
            case ffdhe4096:
                return 4096;
            case ffdhe6144:
                return 6144;
            case ffdhe8192:
                return 8192;
            default:
                return 0;
            }
        }

        public static string GetFiniteFieldName(int namedGroup)
        {
            if (RefersToASpecificFiniteField(namedGroup))
            {
                return FiniteFieldNames[namedGroup - ffdhe2048];
            }

            return null;
        }

        public static int GetHybridFirst(int namedGroup)
        {
            switch (namedGroup)
            {
            case SecP256r1MLKEM768:
                return secp256r1;
            case X25519MLKEM768:
                return MLKEM768;
            case SecP384r1MLKEM1024:
                return secp384r1;
            case curveSM2MLKEM768:
                return curveSM2;
            default:
                return -1;
            }
        }

        public static int GetHybridSecond(int namedGroup)
        {
            switch (namedGroup)
            {
            case SecP256r1MLKEM768:
                return MLKEM768;
            case X25519MLKEM768:
                return x25519;
            case SecP384r1MLKEM1024:
                return MLKEM1024;
            case curveSM2MLKEM768:
                return MLKEM768;
            default:
                return -1;
            }
        }

        // TODO Temporary until crypto implementations become more self-documenting around lengths
        internal static int GetHybridSplitClientShare(int namedGroup)
        {
            switch (namedGroup)
            {
            case curveSM2:
            case secp256r1:
                return 65;
            case secp384r1:
                return 97;
            case MLKEM768:
                return 1184;
            }
            return -1;
        }

        // TODO Temporary until crypto implementations become more self-documenting around lengths
        internal static int GetHybridSplitServerShare(int namedGroup)
        {
            switch (namedGroup)
            {
            case curveSM2:
            case secp256r1:
                return 65;
            case secp384r1:
                return 97;
            case MLKEM768:
                return 1088;
            }
            return -1;
        }

        public static string GetKemName(int namedGroup)
        {
            switch (namedGroup)
            {
            case MLKEM512:
                return "ML-KEM-512";
            case MLKEM768:
                return "ML-KEM-768";
            case MLKEM1024:
                return "ML-KEM-1024";
            default:
                return null;
            }
        }

        /// <summary>Return the maximum char 2 curve bits.</summary>
        public static int GetMaximumChar2CurveBits()
        {
            return 571;
        }

        /// <summary>Return the maximum curve bits.</summary>
        public static int GetMaximumCurveBits()
        {
            return 571;
        }

        /// <summary>Return the maximum finite field bits.</summary>
        public static int GetMaximumFiniteFieldBits()
        {
            return 8192;
        }

        /// <summary>Return the maximum prime curve bits.</summary>
        public static int GetMaximumPrimeCurveBits()
        {
            return 521;
        }

        public static string GetName(int namedGroup)
        {
            if (IsPrivate(namedGroup))
            {
                return "PRIVATE";
            }

            switch (namedGroup)
            {
            case x25519:
                return "x25519";
            case x448:
                return "x448";
            case brainpoolP256r1tls13:
                return "brainpoolP256r1tls13";
            case brainpoolP384r1tls13:
                return "brainpoolP384r1tls13";
            case brainpoolP512r1tls13:
                return "brainpoolP512r1tls13";
            case GC256A:
                return "GC256A";
            case GC256B:
                return "GC256B";
            case GC256C:
                return "GC256C";
            case GC256D:
                return "GC256D";
            case GC512A:
                return "GC512A";
            case GC512B:
                return "GC512B";
            case GC512C:
                return "GC512C";
            case curveSM2:
                return "curveSM2";
            case MLKEM512:
                return "MLKEM512";
            case MLKEM768:
                return "MLKEM768";
            case MLKEM1024:
                return "MLKEM1024";
            case SecP256r1MLKEM768:
                return "SecP256r1MLKEM768";
            case X25519MLKEM768:
                return "X25519MLKEM768";
            case SecP384r1MLKEM1024:
                return "SecP384r1MLKEM1024";
            case curveSM2MLKEM768:
                return "curveSM2MLKEM768";
            case arbitrary_explicit_prime_curves:
                return "arbitrary_explicit_prime_curves";
            case arbitrary_explicit_char2_curves:
                return "arbitrary_explicit_char2_curves";
            }

            string standardName = GetStandardName(namedGroup);
            if (null != standardName)
            {
                return standardName;
            }

            return "UNKNOWN";
        }

        public static string GetStandardName(int namedGroup)
        {
            string curveName = GetCurveName(namedGroup);
            if (null != curveName)
                return curveName;

            string finiteFieldName = GetFiniteFieldName(namedGroup);
            if (null != finiteFieldName)
                return finiteFieldName;

            string kemName = GetKemName(namedGroup);
            if (null != kemName)
                return kemName;

            return null;
        }

        public static string GetText(int namedGroup)
        {
            return GetName(namedGroup) + "(" + namedGroup + ")";
        }

        public static bool IsChar2Curve(int namedGroup)
        {
            return (namedGroup >= sect163k1 && namedGroup <= sect571r1)
                || (namedGroup == arbitrary_explicit_char2_curves);
        }

        public static bool IsFiniteField(int namedGroup) => (namedGroup & 0xFFFFFF00) == 0x00000100;

        public static bool IsPrimeCurve(int namedGroup)
        {
            return (namedGroup >= secp160k1 && namedGroup <= curveSM2)
                || (namedGroup == arbitrary_explicit_prime_curves);
        }

        public static bool IsPrivate(int namedGroup)
        {
            return (namedGroup >> 2) == 0x7F || (namedGroup >> 8) == 0xFE;
        }

        public static bool IsValid(int namedGroup)
        {
            return RefersToASpecificGroup(namedGroup)
                || IsPrivate(namedGroup)
                || (namedGroup >= arbitrary_explicit_prime_curves && namedGroup <= arbitrary_explicit_char2_curves);
        }

        public static bool RefersToAnECDHCurve(int namedGroup)
        {
            return RefersToASpecificCurve(namedGroup);
        }

        public static bool RefersToAnECDSACurve(int namedGroup)
        {
            /*
             * TODO[RFC 8998] Double-check whether this method is only being used to mean
             * "signature-capable" or specifically ECDSA, and consider curveSM2 behaviour
             * accordingly.
             */
            return RefersToASpecificCurve(namedGroup)
                && !RefersToAnXDHCurve(namedGroup);
        }

        public static bool RefersToAnXDHCurve(int namedGroup)
        {
            return namedGroup >= x25519 && namedGroup <= x448;
        }

        public static bool RefersToASpecificCurve(int namedGroup)
        {
            return namedGroup >= sect163k1 && namedGroup <= curveSM2;
        }

        public static bool RefersToASpecificFiniteField(int namedGroup)
        {
            return namedGroup >= ffdhe2048 && namedGroup <= ffdhe8192;
        }

        public static bool RefersToASpecificGroup(int namedGroup)
        {
            return RefersToASpecificCurve(namedGroup)
                || RefersToASpecificFiniteField(namedGroup)
                || RefersToASpecificHybrid(namedGroup)
                || RefersToASpecificKem(namedGroup);
        }

        public static bool RefersToASpecificHybrid(int namedGroup)
        {
            switch (namedGroup)
            {
            case SecP256r1MLKEM768:
            case X25519MLKEM768:
            case SecP384r1MLKEM1024:
            case curveSM2MLKEM768:
                return true;
            default:
                return false;
            }
        }

        public static bool RefersToASpecificKem(int namedGroup)
        {
            switch (namedGroup)
            {
            case MLKEM512:
            case MLKEM768:
            case MLKEM1024:
                return true;
            default:
                return false;
            }
        }
    }
}
