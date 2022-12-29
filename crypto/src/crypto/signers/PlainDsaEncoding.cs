using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class PlainDsaEncoding
        : IDsaEncoding
    {
        public static readonly PlainDsaEncoding Instance = new PlainDsaEncoding();

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

        public virtual byte[] Encode(BigInteger n, BigInteger r, BigInteger s)
        {
            int valueLength = BigIntegers.GetUnsignedByteLength(n);
            byte[] result = new byte[valueLength * 2];
            EncodeValue(n, r, result, 0, valueLength);
            EncodeValue(n, s, result, valueLength, valueLength);
            return result;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int Encode(BigInteger n, BigInteger r, BigInteger s, Span<byte> output)
        {
            int valueLength = BigIntegers.GetUnsignedByteLength(n);
            int resultLength = valueLength * 2;
            EncodeValue(n, r, output[..valueLength]);
            EncodeValue(n, s, output[valueLength..resultLength]);
            return resultLength;
        }
#endif

        public virtual int GetMaxEncodingSize(BigInteger n)
        {
            return BigIntegers.GetUnsignedByteLength(n) * 2;
        }

        protected virtual BigInteger CheckValue(BigInteger n, BigInteger x)
        {
            if (x.SignValue < 0 || x.CompareTo(n) >= 0)
                throw new ArgumentException("Value out of range", "x");

            return x;
        }

        protected virtual BigInteger DecodeValue(BigInteger n, byte[] buf, int off, int len)
        {
            return CheckValue(n, new BigInteger(1, buf, off, len));
        }

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
