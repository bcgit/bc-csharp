using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>
    /// SM2 public key encryption engine - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
    /// </summary>
    public class SM2Engine
    {
        public enum Mode
        {
            C1C2C3, C1C3C2
        }

        private readonly IDigest mDigest;
        private readonly Mode mMode;

        private bool mForEncryption;
        private ECKeyParameters mECKey;
        private ECDomainParameters mECParams;
        private int mCurveLength;
        private SecureRandom mRandom;

        public SM2Engine()
            : this(new SM3Digest())
        {
        }

        public SM2Engine(Mode mode)
            : this(new SM3Digest(), mode)
        {
        }

        public SM2Engine(IDigest digest)
            : this(digest, Mode.C1C2C3)
        {
        }

        public SM2Engine(IDigest digest, Mode mode)
        {
            mDigest = digest;
            mMode = mode;
        }

        public virtual void Init(bool forEncryption, ICipherParameters param)
        {
            this.mForEncryption = forEncryption;

            SecureRandom random = null;
            if (param is ParametersWithRandom withRandom)
            {
                param = withRandom.Parameters;
                random = withRandom.Random;
            }

            mECKey = (ECKeyParameters)param;
            mECParams = mECKey.Parameters;

            if (forEncryption)
            {
                mRandom = CryptoServicesRegistrar.GetSecureRandom(random);

                ECPoint s = ((ECPublicKeyParameters)mECKey).Q.Multiply(mECParams.H);
                if (s.IsInfinity)
                    throw new ArgumentException("invalid key: [h]Q at infinity");
            }
            else
            {
                mRandom = null;
            }

            mCurveLength = mECParams.Curve.FieldElementEncodingLength;
        }

        public virtual byte[] ProcessBlock(byte[] input, int inOff, int inLen)
        {
            if ((inOff + inLen) > input.Length || inLen == 0)
                throw new DataLengthException("input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBlock(input.AsSpan(inOff, inLen));
#else
            if (mForEncryption)
            {
                return Encrypt(input, inOff, inLen);
            }
            else
            {
                return Decrypt(input, inOff, inLen);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual byte[] ProcessBlock(ReadOnlySpan<byte> input)
        {
            if (input.Length == 0)
                throw new DataLengthException("input buffer too short");

            if (mForEncryption)
            {
                return Encrypt(input);
            }
            else
            {
                return Decrypt(input);
            }
        }
#endif

        protected virtual ECMultiplier CreateBasePointMultiplier()
        {
            return new FixedPointCombMultiplier();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private byte[] Encrypt(ReadOnlySpan<byte> input)
        {
            byte[] c2 = input.ToArray();

            ECMultiplier multiplier = CreateBasePointMultiplier();

            BigInteger k;
            ECPoint kPB;
            do
            {
                k = NextK();
                kPB = ((ECPublicKeyParameters)mECKey).Q.Multiply(k).Normalize();

                Kdf(mDigest, kPB, c2);
            }
            while (NotEncrypted(c2, input));

            ECPoint c1P = multiplier.Multiply(mECParams.G, k).Normalize();

            int c1PEncodedLength = c1P.GetEncodedLength(false);
            Span<byte> c1 = c1PEncodedLength <= 512
                ? stackalloc byte[c1PEncodedLength]
                : new byte[c1PEncodedLength];
            c1P.EncodeTo(false, c1);

            AddFieldElement(mDigest, kPB.AffineXCoord);
            mDigest.BlockUpdate(input);
            AddFieldElement(mDigest, kPB.AffineYCoord);

            int digestSize = mDigest.GetDigestSize();
            Span<byte> c3 = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            mDigest.DoFinal(c3);

            switch (mMode)
            {
            case Mode.C1C3C2:
                return Arrays.Concatenate(c1, c3, c2);
            default:
                return Arrays.Concatenate(c1, c2, c3);
            }
        }

        private byte[] Decrypt(ReadOnlySpan<byte> input)
        {
            int c1Length = mCurveLength * 2 + 1;
            ECPoint c1P = mECParams.Curve.DecodePoint(input[..c1Length]);

            ECPoint s = c1P.Multiply(mECParams.H);
            if (s.IsInfinity)
                throw new InvalidCipherTextException("[h]C1 at infinity");

            c1P = c1P.Multiply(((ECPrivateKeyParameters)mECKey).D).Normalize();

            int digestSize = mDigest.GetDigestSize();
            int c2Length = input.Length - c1Length - digestSize;
            byte[] c2 = new byte[c2Length];

            if (mMode == Mode.C1C3C2)
            {
                input[(c1Length + digestSize)..].CopyTo(c2);
            }
            else
            {
                input[c1Length..(c1Length + c2Length)].CopyTo(c2);
            }

            Kdf(mDigest, c1P, c2);

            AddFieldElement(mDigest, c1P.AffineXCoord);
            mDigest.BlockUpdate(c2);
            AddFieldElement(mDigest, c1P.AffineYCoord);

            Span<byte> c3 = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            mDigest.DoFinal(c3);

            int check = 0;
            if (mMode == Mode.C1C3C2)
            {
                for (int i = 0; i != c3.Length; i++)
                {
                    check |= c3[i] ^ input[c1Length + i];
                }
            }
            else
            {
                for (int i = 0; i != c3.Length; i++)
                {
                    check |= c3[i] ^ input[c1Length + c2.Length + i];
                }
            }

            c3.Fill(0);

            if (check != 0)
            {
                Arrays.Fill(c2, 0);
                throw new InvalidCipherTextException("invalid cipher text");
            }

            return c2;
        }

        private bool NotEncrypted(ReadOnlySpan<byte> encData, ReadOnlySpan<byte> input)
        {
            for (int i = 0; i != encData.Length; i++)
            {
                if (encData[i] != input[i])
                    return false;
            }

            return true;
        }
#else
        private byte[] Encrypt(byte[] input, int inOff, int inLen)
        {
            byte[] c2 = new byte[inLen];

            Array.Copy(input, inOff, c2, 0, c2.Length);

            ECMultiplier multiplier = CreateBasePointMultiplier();

            BigInteger k;
            ECPoint kPB;
            do
            {
                k = NextK();
                kPB = ((ECPublicKeyParameters)mECKey).Q.Multiply(k).Normalize();

                Kdf(mDigest, kPB, c2);
            }
            while (NotEncrypted(c2, input, inOff));

            ECPoint c1P = multiplier.Multiply(mECParams.G, k).Normalize();

            byte[] c1 = c1P.GetEncoded(false);

            AddFieldElement(mDigest, kPB.AffineXCoord);
            mDigest.BlockUpdate(input, inOff, inLen);
            AddFieldElement(mDigest, kPB.AffineYCoord);

            byte[] c3 = DigestUtilities.DoFinal(mDigest);

            switch (mMode)
            {
            case Mode.C1C3C2:
                return Arrays.ConcatenateAll(c1, c3, c2);
            default:
                return Arrays.ConcatenateAll(c1, c2, c3);
            }
        }

        private byte[] Decrypt(byte[] input, int inOff, int inLen)
        {
            byte[] c1 = new byte[mCurveLength * 2 + 1];

            Array.Copy(input, inOff, c1, 0, c1.Length);

            ECPoint c1P = mECParams.Curve.DecodePoint(c1);

            ECPoint s = c1P.Multiply(mECParams.H);
            if (s.IsInfinity)
                throw new InvalidCipherTextException("[h]C1 at infinity");

            c1P = c1P.Multiply(((ECPrivateKeyParameters)mECKey).D).Normalize();

            int digestSize = mDigest.GetDigestSize();
            byte[] c2 = new byte[inLen - c1.Length - digestSize];

            if (mMode == Mode.C1C3C2)
            {
                Array.Copy(input, inOff + c1.Length + digestSize, c2, 0, c2.Length);
            }
            else
            {
                Array.Copy(input, inOff + c1.Length, c2, 0, c2.Length);
            }

            Kdf(mDigest, c1P, c2);

            AddFieldElement(mDigest, c1P.AffineXCoord);
            mDigest.BlockUpdate(c2, 0, c2.Length);
            AddFieldElement(mDigest, c1P.AffineYCoord);

            byte[] c3 = DigestUtilities.DoFinal(mDigest);

            int check = 0;
            if (mMode == Mode.C1C3C2)
            {
                for (int i = 0; i != c3.Length; i++)
                {
                    check |= c3[i] ^ input[inOff + c1.Length + i];
                }
            }
            else
            {
                for (int i = 0; i != c3.Length; i++)
                {
                    check |= c3[i] ^ input[inOff + c1.Length + c2.Length + i];
                }
            }

            Arrays.Fill(c1, 0);
            Arrays.Fill(c3, 0);

            if (check != 0)
            {
               Arrays.Fill(c2, 0);
               throw new InvalidCipherTextException("invalid cipher text");
            }

            return c2;
        }

        private bool NotEncrypted(byte[] encData, byte[] input, int inOff)
        {
            for (int i = 0; i != encData.Length; i++)
            {
                if (encData[i] != input[inOff + i])
                    return false;
            }

            return true;
        }
#endif

        private void Kdf(IDigest digest, ECPoint c1, byte[] encData)
        {
            int digestSize = digest.GetDigestSize();
            int bufSize = System.Math.Max(4, digestSize);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = bufSize <= 128
                ? stackalloc byte[bufSize]
                : new byte[bufSize];
#else
            byte[] buf = new byte[bufSize];
#endif
            int off = 0;

            IMemoable memo = digest as IMemoable;
            IMemoable copy = null;

            if (memo != null)
            {
                AddFieldElement(digest, c1.AffineXCoord);
                AddFieldElement(digest, c1.AffineYCoord);
                copy = memo.Copy();
            }

            uint ct = 0;

            while (off < encData.Length)
            {
                if (memo != null)
                {
                    memo.Reset(copy);
                }
                else
                {
                    AddFieldElement(digest, c1.AffineXCoord);
                    AddFieldElement(digest, c1.AffineYCoord);
                }

                int xorLen = System.Math.Min(digestSize, encData.Length - off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Pack.UInt32_To_BE(++ct, buf);
                digest.BlockUpdate(buf[..4]);
                digest.DoFinal(buf);
                Bytes.XorTo(xorLen, buf, encData.AsSpan(off));
#else
                Pack.UInt32_To_BE(++ct, buf, 0);
                digest.BlockUpdate(buf, 0, 4);
                digest.DoFinal(buf, 0);
                Bytes.XorTo(xorLen, buf, 0, encData, off);
#endif
                off += xorLen;
            }
        }

        private BigInteger NextK()
        {
            int qBitLength = mECParams.N.BitLength;

            BigInteger k;
            do
            {
                k = new BigInteger(qBitLength, mRandom);
            }
            while (k.SignValue == 0 || k.CompareTo(mECParams.N) >= 0);

            return k;
        }

        private void AddFieldElement(IDigest digest, ECFieldElement v)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int encodedLength = v.GetEncodedLength();
            Span<byte> p = encodedLength <= 128
                ? stackalloc byte[encodedLength]
                : new byte[encodedLength];
            v.EncodeTo(p);
            digest.BlockUpdate(p);
#else
            byte[] p = v.GetEncoded();
            digest.BlockUpdate(p, 0, p.Length);
#endif
        }
    }
}
