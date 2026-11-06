using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    internal static class DHKeyGeneratorHelper
    {
        /// <summary>
        /// Refuse a private value length l below twice the security strength of p (the 2s floor of SP 800-56A Rev3
        /// sec. 5.6.1.1), unless <see cref="Properties.DHAllowShortPrivateValue"/> is set.
        /// </summary>
        /// <remarks>
        /// l may come with parameters chosen by someone else, and an l-bit private value can be recovered with about
        /// 2^(l/2) work. See <see cref="SecurityStrengthFor(BigInteger)"/> for the strength used.
        /// </remarks>
        internal static void CheckPrivateValueLength(BigInteger p, int l, string paramName)
        {
            if (l == 0)
                return;

            int minL = 2 * SecurityStrengthFor(p);
            if (l < minL && !Properties.GetBoolean(Properties.DHAllowShortPrivateValue, defaultValue: false))
            {
                throw new ArgumentException(
                    $"when l value specified, it must not be less than {minL} for a {p.BitLength} bit p", paramName);
            }
        }

        /// <summary>The security strength s of p, in bits.</summary>
        /// <remarks>
        /// From 4096 bits up this follows the strengths SP 800-56A Rev3 Appendix D assigns the safe-prime groups (152,
        /// 176 and 200 bits for 4096, 6144 and 8192-bit p, the values DHStandardGroups uses for l), applied as steps to
        /// any p of at least that size, which is BC's extension of the table; otherwise, and where it is higher, the
        /// SP 800-57 strength.
        /// </remarks>
        internal static int SecurityStrengthFor(BigInteger p)
        {
            int pBits = p.BitLength;
            if (pBits >= 15360)
                return 256;
            if (pBits >= 8192)
                return 200; // SP 800-56A Appendix D
            if (pBits >= 7680)
                return 192;
            if (pBits >= 6144)
                return 176; // SP 800-56A Appendix D
            if (pBits >= 4096)
                return 152; // SP 800-56A Appendix D
            if (pBits >= 3072)
                return 128;
            if (pBits >= 2048)
                return 112;
            if (pBits >= 1024)
                return 80;
            return 20;
        }

        /// <summary>
        /// Generate a private value x and public value y, redrawing x while y falls outside [2, p - 2] (an x that is a
        /// multiple of ord(g), or ord(g)/2).
        /// </summary>
        /// <remarks>
        /// <see cref="DHParameters"/> already requires g to lie in [2, p - 2], so a suitable x always exists.
        /// </remarks>
        internal static void CalculateKeyPair(DHParameters dhParams, SecureRandom random, out BigInteger x,
            out BigInteger y)
        {
            BigInteger pSub2 = dhParams.P.Subtract(BigInteger.Two);

            for (;;)
            {
                x = CalculatePrivate(dhParams, random);
                y = CalculatePublic(dhParams, x);
                if (y.CompareTo(BigInteger.Two) >= 0 && y.CompareTo(pSub2) <= 0)
                    return;
            }
        }

        private static BigInteger CalculatePrivate(DHParameters dhParams, SecureRandom random)
        {
            int limit = dhParams.L;

            if (limit != 0)
            {
                int minWeight = limit >> 2;

                /*
                 * PKCS#3 sec. 7.1: when l is given, x is an l-bit integer, 2^(l-1) <= x < 2^l. At l == bitLength(p)
                 * that can be at or above p - 1, which is harmless: only x mod ord(g) matters, and the values reducing
                 * below 2^(l-1) are disjoint from those that do not, so a single draw still carries l - 1 bits.
                 */
                for (;;)
                {
                    BigInteger x = new BigInteger(limit, random).SetBit(limit - 1);
                    if (WNafUtilities.GetNafWeight(x) >= minWeight)
                        return x;
                }
            }

            BigInteger min = BigInteger.Two;
            int m = dhParams.M;
            if (m != 0)
            {
                min = BigInteger.One.ShiftLeft(m - 1);
            }

            BigInteger q = dhParams.Q ?? dhParams.P;
            BigInteger max = q.Subtract(BigInteger.Two);

            {
                int minWeight = max.BitLength >> 2;
                for (;;)
                {
                    BigInteger x = BigIntegers.CreateRandomInRange(min, max, random);
                    if (WNafUtilities.GetNafWeight(x) >= minWeight)
                        return x;
                }
            }
        }

        private static BigInteger CalculatePublic(DHParameters dhParams, BigInteger x) =>
            dhParams.G.ModPow(x, dhParams.P);
    }
}
