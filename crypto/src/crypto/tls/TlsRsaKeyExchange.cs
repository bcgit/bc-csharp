using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public static class TlsRsaKeyExchange
    {
        public const int PreMasterSecretLength = 48;

        public static byte[] DecryptPreMasterSecret(byte[] buf, int off, int len, RsaKeyParameters privateKey,
            int protocolVersion, SecureRandom secureRandom)
        {
            if (buf == null || len < 1 || len > GetInputLimit(privateKey) || off < 0 || off > buf.Length - len)
                throw new ArgumentException("input not a valid EncryptedPreMasterSecret");

            if (!privateKey.IsPrivate)
                throw new ArgumentException("must be an RSA private key", nameof(privateKey));

            BigInteger modulus = privateKey.Modulus;
            int bitLength = modulus.BitLength;
            if (bitLength < 512)
                throw new ArgumentException("must be at least 512 bits", nameof(privateKey));

            if ((protocolVersion & 0xFFFF) != protocolVersion)
                throw new ArgumentException("must be a 16 bit value", nameof(protocolVersion));

            secureRandom = CryptoServicesRegistrar.GetSecureRandom(secureRandom);

            /*
             * Generate random bytes we can use as a Pre-Master-Secret if the decrypted value is invalid.
             */
            byte[] result = new byte[PreMasterSecretLength];
            secureRandom.NextBytes(result);

            try
            {
                BigInteger input = ConvertInput(modulus, buf, off, len);
                byte[] encoding = RsaBlinded(privateKey, input, secureRandom);

                int pkcs1Length = (bitLength - 1) / 8;
                int plainTextOffset = encoding.Length - PreMasterSecretLength;

                int badEncodingMask = CheckPkcs1Encoding2(encoding, pkcs1Length, PreMasterSecretLength);
                int badVersionMask = -(Pack.BE_To_UInt16(encoding, plainTextOffset) ^ protocolVersion) >> 31;
                int fallbackMask = badEncodingMask | badVersionMask;

                for (int i = 0; i < PreMasterSecretLength; ++i)
                {
                    result[i] = (byte)((result[i] & fallbackMask) | (encoding[plainTextOffset + i] & ~fallbackMask));
                }

                Arrays.Fill(encoding, 0x00);
            }
            catch (Exception)
            {
                /*
                 * Decryption should never throw an exception; return a random value instead.
                 *
                 * In any case, a TLS server MUST NOT generate an alert if processing an RSA-encrypted premaster
                 * secret message fails, or the version number is not as expected. Instead, it MUST continue the
                 * handshake with a randomly generated premaster secret.
                 */
            }

            return result;
        }

        public static int GetInputLimit(RsaKeyParameters privateKey)
        {
            return (privateKey.Modulus.BitLength + 7) / 8;
        }

        private static int CAddTo(int len, int cond, byte[] x, byte[] z)
        {
            Debug.Assert(cond == 0 || cond == -1);

            int c = 0;
            for (int i = len - 1; i >= 0; --i)
            {
                c += z[i] + (x[i] & cond);
                z[i] = (byte)c;
                c >>= 8;
            }
            return c;
        }

        /**
         * Check the argument is a valid encoding with type 2 of a plaintext with the given length. Returns 0 if
         * valid, or -1 if invalid.
         */
        private static int CheckPkcs1Encoding2(byte[] buf, int pkcs1Length, int plaintextLength)
        {
            // The header should be at least 10 bytes
            int errorSign = pkcs1Length - plaintextLength - 10;

            int firstPadPos = buf.Length - pkcs1Length;
            int lastPadPos = buf.Length - 1 - plaintextLength;

            // Any leading bytes should be zero
            for (int i = 0; i < firstPadPos; ++i)
            {
                errorSign |= -buf[i];
            }

            // The first byte should be 0x02
            errorSign |= -(buf[firstPadPos] ^ 0x02);

            // All pad bytes before the last one should be non-zero
            for (int i = firstPadPos + 1; i < lastPadPos; ++i)
            {
                errorSign |= buf[i] - 1;
            }

            // Last pad byte should be zero
            errorSign |= -buf[lastPadPos];

            return errorSign >> 31;
        }

        private static BigInteger ConvertInput(BigInteger modulus, byte[] buf, int off, int len)
        {
            BigInteger input = BigIntegers.FromUnsignedByteArray(buf, off, len);

            if (input.CompareTo(BigInteger.One) <= 0)
                throw new DataLengthException("input too small for RSA cipher.");

            if (input.CompareTo(modulus.Subtract(BigInteger.One)) >= 0)
                throw new DataLengthException("input too large for RSA cipher.");

            return input;
        }

        private static BigInteger Rsa(RsaKeyParameters privateKey, BigInteger input)
        {
            return input.ModPow(privateKey.Exponent, privateKey.Modulus);
        }

        private static byte[] RsaBlinded(RsaKeyParameters privateKey, BigInteger input, SecureRandom secureRandom)
        {
            BigInteger modulus = privateKey.Modulus;
            int resultSize = (modulus.BitLength + 7) / 8;

            if (!(privateKey is RsaPrivateCrtKeyParameters crtKey))
                return BigIntegers.AsUnsignedByteArray(resultSize, Rsa(privateKey, input));

            BigInteger e = crtKey.PublicExponent;
            Debug.Assert(e != null);

            BigInteger r = BigIntegers.CreateRandomInRange(BigInteger.One, modulus.Subtract(BigInteger.One),
                secureRandom);
            BigInteger blind = r.ModPow(e, modulus);
            BigInteger unblind = BigIntegers.ModOddInverse(modulus, r);

            BigInteger blindedInput = blind.ModMultiply(input, modulus);
            BigInteger blindedResult = RsaCrt(crtKey, blindedInput);
            BigInteger offsetResult = unblind.Add(BigInteger.One).ModMultiply(blindedResult, modulus);

            /*
             * BigInteger conversion time is not constant, but is only done for blinded or public values.
             */
            byte[] blindedResultBytes = BigIntegers.AsUnsignedByteArray(resultSize, blindedResult);
            byte[] modulusBytes = BigIntegers.AsUnsignedByteArray(resultSize, modulus);
            byte[] resultBytes = BigIntegers.AsUnsignedByteArray(resultSize, offsetResult);

            /*
             * A final modular subtraction is done without timing dependencies on the final result. 
             */
            int carry = SubFrom(resultSize, blindedResultBytes, resultBytes);
            CAddTo(resultSize, carry, modulusBytes, resultBytes);

            return resultBytes;
        }

        private static BigInteger RsaCrt(RsaPrivateCrtKeyParameters crtKey, BigInteger input)
        {
            //
            // we have the extra factors, use the Chinese Remainder Theorem - the author
            // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
            // advice regarding the expression of this.
            //
            BigInteger e = crtKey.PublicExponent;
            Debug.Assert(e != null);

            BigInteger p = crtKey.P;
            BigInteger q = crtKey.Q;
            BigInteger dP = crtKey.DP;
            BigInteger dQ = crtKey.DQ;
            BigInteger qInv = crtKey.QInv;

            // mP = ((input mod p) ^ dP)) mod p
            BigInteger mP = input.Remainder(p).ModPow(dP, p);

            // mQ = ((input mod q) ^ dQ)) mod q
            BigInteger mQ = input.Remainder(q).ModPow(dQ, q);

            // h = qInv * (mP - mQ) mod p
            BigInteger h = mP.Subtract(mQ).ModMultiply(qInv, p);

            // m = h * q + mQ
            BigInteger m = h.Multiply(q).Add(mQ);

            // defence against Arjen Lenstra’s CRT attack
            BigInteger check = m.ModPow(e, crtKey.Modulus);
            if (!check.Equals(input))
                throw new InvalidOperationException("RSA engine faulty decryption/signing detected");

            return m;
        }

        private static int SubFrom(int len, byte[] x, byte[] z)
        {
            int c = 0;
            for (int i = len - 1; i >= 0; --i)
            {
                c += z[i] - x[i];
                z[i] = (byte)c;
                c >>= 8;
            }
            return c;
        }
    }
}
