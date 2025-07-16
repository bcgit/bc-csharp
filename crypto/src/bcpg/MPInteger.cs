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

        public MPInteger(BcpgInputStream bcpgIn)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            /*
             * TODO RFC 9580 3.2. When parsing an MPI in a version 6 Key, Signature, or Public Key Encrypted
             * Session Key (PKESK) packet, the implementation MUST check that the encoded length matches the
             * length starting from the most significant non-zero bit; if it doesn't match, reject the packet as
             * malformed.
             */
            bool validateLength = false;

            m_value = ReadMpi(bcpgIn, validateLength);
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

        private static BigInteger ReadMpi(BcpgInputStream bcpgIn, bool validateLength)
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

            if (validateLength && n.BitLength != bitLength)
                throw new IOException("malformed MPI");

            return n;
        }
    }
}
