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

			int lengthInBits = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            int lengthInBytes = (lengthInBits + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (lengthInBytes <= 512)
            {
                Span<byte> span = stackalloc byte[lengthInBytes];
                bcpgIn.ReadFully(span);
                m_val = new BigInteger(1, span);
                return;
            }
#endif

            byte[] bytes = new byte[lengthInBytes];
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
            Span<byte> encoding = stackalloc byte[point.GetEncodedLength(false)];
            point.EncodeTo(false, encoding);
            return new BigInteger(1, encoding);
#else
            return new BigInteger(1, point.GetEncoded(false));
#endif
        }
    }
}
