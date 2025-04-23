using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>A multiple precision integer</remarks>
    public sealed class MPInteger
        : BcpgObject
    {
        private readonly BigInteger m_val;

        public MPInteger(BcpgInputStream bcpgIn)
        {
			if (bcpgIn == null)
				throw new ArgumentNullException(nameof(bcpgIn));

            int lengthInBits = StreamUtilities.RequireUInt16BE(bcpgIn);
            int lengthInBytes = (lengthInBits + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = lengthInBytes <= 512
                ? stackalloc byte[lengthInBytes]
                : new byte[lengthInBytes];
#else
            byte[] bytes = new byte[lengthInBytes];
#endif

            bcpgIn.ReadFully(bytes);
            m_val = new BigInteger(1, bytes);
        }

		public MPInteger(BigInteger val)
        {
			if (val == null)
				throw new ArgumentNullException(nameof(val));
			if (val.SignValue < 0)
				throw new ArgumentException("Values must be positive", nameof(val));

			m_val = val;
        }

        public BigInteger Value => m_val;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteShort((short)m_val.BitLength);
            bcpgOut.Write(m_val.ToByteArrayUnsigned());
        }

        internal static BigInteger ToMpiBigInteger(ECPoint point)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int encodedLength = point.GetEncodedLength(false);
            Span<byte> encoding = encodedLength <= 512
                ? stackalloc byte[encodedLength]
                : new byte[encodedLength];
            point.EncodeTo(false, encoding);
#else
            byte[] encoding = point.GetEncoded(false);
#endif
            return new BigInteger(1, encoding);
        }
    }
}
