using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>The standard ASN.1 (DER) encoding of DSA and ECDSA signatures.</summary>
    // TODO[api] Make sealed (no need for protected virtual methods)
    public class StandardDsaEncoding
        : IDsaEncoding
    {
        /// <summary>The shared instance of <see cref="StandardDsaEncoding"/>.</summary>
        public static readonly StandardDsaEncoding Instance = new StandardDsaEncoding();

        /// <inheritdoc/>
        public virtual BigInteger[] Decode(BigInteger n, byte[] encoding)
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(encoding);
            if (seq.Count == 2)
            {
                BigInteger r = DecodeValue(n, seq, 0);
                BigInteger s = DecodeValue(n, seq, 1);

                byte[] expectedEncoding = Encode(n, r, s);
                if (Arrays.AreEqual(expectedEncoding,  encoding))
                    return new BigInteger[]{ r, s };
            }

            throw new ArgumentException("Malformed signature", nameof(encoding));
        }

        /// <inheritdoc/>
        public virtual byte[] Encode(BigInteger n, BigInteger r, BigInteger s)
        {
            return new DerSequence(
                EncodeValue(n, r),
                EncodeValue(n, s)
            ).GetEncoded(Asn1Encodable.Der);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual int Encode(BigInteger n, BigInteger r, BigInteger s, Span<byte> output)
        {
            byte[] encoding = Encode(n, r, s);
            encoding.CopyTo(output);
            return encoding.Length;
        }
#endif

        /// <inheritdoc/>
        public virtual int GetMaxEncodingSize(BigInteger n)
        {
            return DerSequence.GetEncodingLength(DerInteger.GetEncodingLength(n) * 2);
        }

        /// <summary>
        /// Check that a value is in range: not negative, and below <paramref name="n"/> if that is given.
        /// </summary>
        /// <param name="n">The upper bound (exclusive), or null for no bound.</param>
        /// <param name="x">The value to check.</param>
        /// <returns>The value, if valid.</returns>
        /// <exception cref="ArgumentException">The value is out of range.</exception>
        protected virtual BigInteger CheckValue(BigInteger n, BigInteger x)
        {
            if (x.SignValue < 0 || (null != n && x.CompareTo(n) >= 0))
                throw new ArgumentException("Value out of range", nameof(x));

            return x;
        }

        /// <summary>Decode a value from an element of an ASN.1 sequence.</summary>
        /// <param name="n">The upper bound (exclusive) for the value.</param>
        /// <param name="s">The sequence.</param>
        /// <param name="pos">The position of the element in the sequence.</param>
        /// <returns>The decoded value.</returns>
        protected virtual BigInteger DecodeValue(BigInteger n, Asn1Sequence s, int pos)
        {
            return CheckValue(n, ((DerInteger)s[pos]).Value);
        }

        /// <summary>Encode a value as an ASN.1 INTEGER.</summary>
        /// <param name="n">The upper bound (exclusive) for the value.</param>
        /// <param name="x">The value to encode.</param>
        /// <returns>The encoded value.</returns>
        protected virtual DerInteger EncodeValue(BigInteger n, BigInteger x)
        {
            return new DerInteger(CheckValue(n, x));
        }
    }
}
