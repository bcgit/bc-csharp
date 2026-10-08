using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>A multiple precision integer</remarks>
    public sealed class MPInteger
        : BcpgObject
    {
        private readonly BigInteger m_value;
        private readonly bool m_minimal = true;

        public MPInteger(BcpgInputStream bcpgIn)
            : this(bcpgIn, strict: false)
        {
        }

        /// <summary>Read an MPI.</summary>
        /// <param name="strict">
        /// RFC 9580 3.2: when parsing an MPI in a version 6 key, signature or PKESK packet, the encoded length must
        /// match the length starting from the most significant non-zero bit. With this option, other encodings are
        /// rejected.
        /// </param>
        /// <exception cref="MalformedPacketException">If <paramref name="strict"/> is set and the encoding is not
        /// minimal.</exception>
        internal MPInteger(BcpgInputStream bcpgIn, bool strict)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            m_value = ReadMpi(bcpgIn, out m_minimal);

            if (strict && !m_minimal)
                throw new MalformedPacketException("malformed MPI");
        }

        public MPInteger(BigInteger val)
        {
            if (val == null)
                throw new ArgumentNullException(nameof(val));
            if (val.SignValue < 0)
                throw new ArgumentException("Values must be positive", nameof(val));

            m_value = val;
        }

        public BigInteger Value => m_value;

        /// <summary>Whether the encoded bit length matched the value when this MPI was read.</summary>
        internal bool IsMinimal => m_minimal;

        public override void Encode(BcpgOutputStream bcpgOut) => Encode(bcpgOut, m_value);

        internal static void Encode(BcpgOutputStream bcpgOut, BigInteger n)
        {
            StreamUtilities.WriteUInt16BE(bcpgOut, (ushort)n.BitLength);
            BigIntegers.WriteUnsignedByteArray(bcpgOut, n);
        }

        internal static BigInteger ToMpiBigInteger(ECPoint point)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int encodedLength = point.GetEncodedLength(false);
            Span<byte> encoding = encodedLength <= 512
                ? stackalloc byte[encodedLength]
                : new byte[encodedLength];
            point.EncodeTo(compressed: false, encoding);
#else
            byte[] encoding = point.GetEncoded(compressed: false);
#endif
            return new BigInteger(1, encoding);
        }

        private static BigInteger ReadMpi(BcpgInputStream bcpgIn, out bool minimal)
        {
            int bitLength = StreamUtilities.RequireUInt16BE(bcpgIn);
            int byteLength = (bitLength + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = byteLength <= 512
                ? stackalloc byte[byteLength]
                : new byte[byteLength];
#else
            byte[] bytes = new byte[byteLength];
#endif

            bcpgIn.ReadFully(bytes);
            BigInteger n = new BigInteger(1, bytes);

            minimal = n.BitLength == bitLength;

            return n;
        }
    }
}
