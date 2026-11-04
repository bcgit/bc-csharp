using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// The plain (r || s) encoding of DSA and ECDSA signatures, as used by P1363 and in some protocols.
    /// </summary>
    // TODO[api] Make sealed (no need for protected virtual methods)
    public class PlainDsaEncoding
        : IDsaEncoding
    {
        /// <summary>The shared instance of <see cref="PlainDsaEncoding"/>.</summary>
        public static readonly PlainDsaEncoding Instance = new PlainDsaEncoding();

        /// <inheritdoc/>
        public virtual BigInteger[] Decode(BigInteger n, byte[] encoding)
        {
            int valueLength = BigIntegers.GetUnsignedByteLength(n);
            if (encoding.Length != valueLength * 2)
                throw new ArgumentException("Encoding has incorrect length", "encoding");

            return new BigInteger[] {
                DecodeValue(n, encoding, 0, valueLength),
                DecodeValue(n, encoding, valueLength, valueLength),
            };
        }

        /// <inheritdoc/>
        public virtual byte[] Encode(BigInteger n, BigInteger r, BigInteger s)
        {
            int valueLength = BigIntegers.GetUnsignedByteLength(n);
            byte[] result = new byte[valueLength * 2];
            EncodeValue(n, r, result, 0, valueLength);
            EncodeValue(n, s, result, valueLength, valueLength);
            return result;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual int Encode(BigInteger n, BigInteger r, BigInteger s, Span<byte> output)
        {
            int valueLength = BigIntegers.GetUnsignedByteLength(n);
            int resultLength = valueLength * 2;
            EncodeValue(n, r, output[..valueLength]);
            EncodeValue(n, s, output[valueLength..resultLength]);
            return resultLength;
        }
#endif

        /// <inheritdoc/>
        public virtual int GetMaxEncodingSize(BigInteger n)
        {
            return BigIntegers.GetUnsignedByteLength(n) * 2;
        }

        /// <summary>Check that a value is in the range <c>[0, n)</c>.</summary>
        /// <param name="n">The upper bound (exclusive).</param>
        /// <param name="x">The value to check.</param>
        /// <returns>The value, if valid.</returns>
        /// <exception cref="ArgumentException">The value is out of range.</exception>
        protected virtual BigInteger CheckValue(BigInteger n, BigInteger x)
        {
            if (x.SignValue < 0 || x.CompareTo(n) >= 0)
                throw new ArgumentException("Value out of range", "x");

            return x;
        }

        /// <summary>Decode a value from a fixed-size, unsigned big-endian encoding.</summary>
        /// <param name="n">The upper bound (exclusive) for the value.</param>
        /// <param name="buf">The buffer holding the encoding.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the encoding starts.</param>
        /// <param name="len">The length of the encoding.</param>
        /// <returns>The decoded value.</returns>
        protected virtual BigInteger DecodeValue(BigInteger n, byte[] buf, int off, int len)
        {
            return CheckValue(n, new BigInteger(1, buf, off, len));
        }

        /// <summary>Encode a value as a fixed-size, unsigned big-endian encoding, left padded with zeros.</summary>
        /// <param name="n">The upper bound (exclusive) for the value.</param>
        /// <param name="x">The value to encode.</param>
        /// <param name="buf">The buffer to write to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        /// <param name="len">The size of the encoding.</param>
        protected virtual void EncodeValue(BigInteger n, BigInteger x, byte[] buf, int off, int len)
        {
            byte[] bs = CheckValue(n, x).ToByteArrayUnsigned();
            int bsOff = System.Math.Max(0, bs.Length - len);
            int bsLen = bs.Length - bsOff;

            int pos = len - bsLen;
            Arrays.Fill(buf, off, off + pos, 0);
            Array.Copy(bs, bsOff, buf, off + pos, bsLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Encode a value as a fixed-size, unsigned big-endian encoding, left padded with zeros.</summary>
        /// <param name="n">The upper bound (exclusive) for the value.</param>
        /// <param name="x">The value to encode.</param>
        /// <param name="buffer">The buffer to write to.</param>
        protected virtual void EncodeValue(BigInteger n, BigInteger x, Span<byte> buffer)
        {
            byte[] bs = CheckValue(n, x).ToByteArrayUnsigned();
            int bsOff = System.Math.Max(0, bs.Length - buffer.Length);
            int bsLen = bs.Length - bsOff;

            int pos = buffer.Length - bsLen;
            buffer[..pos].Fill(0x00);
            bs.AsSpan(bsOff, bsLen).CopyTo(buffer[pos..]);
        }
#endif
    }
}
