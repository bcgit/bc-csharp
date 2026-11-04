using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>Utility methods for converting between integers and octet strings, as defined in ANSI X9.62.</summary>
    // TODO[api] Make static
    public abstract class X9IntegerConverter
    {
        /// <summary>Get the length in bytes of the encoding of a field element.</summary>
        /// <param name="fe">The field element.</param>
        /// <returns>The length in bytes.</returns>
        public static int GetByteLength(ECFieldElement fe) => fe.GetEncodedLength();

        /// <summary>Get the length in bytes of the encoding of an element of the field of a curve.</summary>
        /// <param name="c">The curve.</param>
        /// <returns>The length in bytes.</returns>
        public static int GetByteLength(ECCurve c) => c.FieldElementEncodingLength;

        /// <summary>Convert an integer to an unsigned big-endian byte array of a given length.</summary>
        /// <param name="s">The integer.</param>
        /// <param name="qLength">The length of the result in bytes.</param>
        /// <returns>The bytes, with leading zeros as needed.</returns>
        public static byte[] IntegerToBytes(BigInteger s, int qLength)
        {
            byte[] bytes = s.ToByteArrayUnsigned();

            if (qLength < bytes.Length)
            {
                byte[] tmp = new byte[qLength];
                Array.Copy(bytes, bytes.Length - tmp.Length, tmp, 0, tmp.Length);
                return tmp;
            }
            else if (qLength > bytes.Length)
            {
                byte[] tmp = new byte[qLength];
                Array.Copy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);
                return tmp;
            }

            return bytes;
        }
    }
}
