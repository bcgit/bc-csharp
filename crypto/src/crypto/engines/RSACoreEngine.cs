using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>This does your basic RSA algorithm.</summary>
    public class RsaCoreEngine
        : IRsa
    {
        private RsaKeyParameters m_key;
        private bool m_forEncryption;
        private int m_bitSize;

        /**
         * initialise the RSA engine.
         *
         * @param forEncryption true if we are encrypting, false otherwise.
         * @param param the necessary RSA key parameters.
         */
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            parameters = ParameterUtilities.IgnoreRandom(parameters);

            m_key = parameters as RsaKeyParameters ?? throw new InvalidKeyException("Not an RSA key");
            m_forEncryption = forEncryption;
            m_bitSize = m_key.Modulus.BitLength;
        }

        /**
         * Return the maximum size for an input block to this engine.
         * For RSA this is always one byte less than the key size on
         * encryption, and the same length as the key size on decryption.
         *
         * @return maximum size for an input block.
         */
        public virtual int GetInputBlockSize()
        {
            CheckInitialised();

            if (m_forEncryption)
            {
                return (m_bitSize - 1) / 8;
            }

            return (m_bitSize + 7) / 8;
        }

        /**
         * Return the maximum size for an output block to this engine.
         * For RSA this is always one byte less than the key size on
         * decryption, and the same length as the key size on encryption.
         *
         * @return maximum size for an output block.
         */
        public virtual int GetOutputBlockSize()
        {
            CheckInitialised();

            if (m_forEncryption)
            {
                return (m_bitSize + 7) / 8;
            }

            return (m_bitSize - 1) / 8;
        }

        public virtual BigInteger ConvertInput(byte[] inBuf, int inOff, int inLen)
        {
            CheckInitialised();

            int maxLength = (m_bitSize + 7) / 8;

            if (inLen > maxLength)
                throw new DataLengthException("input too large for RSA cipher.");

            BigInteger input = new BigInteger(1, inBuf, inOff, inLen);

            if (input.CompareTo(BigInteger.One) <= 0)
                throw new DataLengthException("input too small for RSA cipher.");

            if (input.CompareTo(m_key.Modulus.Subtract(BigInteger.One)) >= 0)
                throw new DataLengthException("input too large for RSA cipher.");

            return input;
        }

        public virtual byte[] ConvertOutput(BigInteger result)
        {
            CheckInitialised();

            return m_forEncryption
                ? BigIntegers.AsUnsignedByteArray(GetOutputBlockSize(), result)
                : BigIntegers.AsUnsignedByteArray(result);
        }

        public virtual BigInteger ProcessBlock(BigInteger input)
        {
            CheckInitialised();

            if (!(m_key is RsaPrivateCrtKeyParameters crt))
                return input.ModPow(m_key.Exponent, m_key.Modulus);

            //
            // we have the extra factors, use the Chinese Remainder Theorem - the author
            // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
            // advice regarding the expression of this.
            //
            BigInteger p = crt.P;
            BigInteger q = crt.Q;
            BigInteger dP = crt.DP;
            BigInteger dQ = crt.DQ;
            BigInteger qInv = crt.QInv;

            // mP = ((input Mod p) ^ dP)) Mod p
            BigInteger mP = input.Remainder(p).ModPow(dP, p);

            // mQ = ((input Mod q) ^ dQ)) Mod q
            BigInteger mQ = input.Remainder(q).ModPow(dQ, q);

            // h = qInv * (mP - mQ) Mod p
            BigInteger h = mP.Subtract(mQ).Multiply(qInv).Mod(p);

            // m = h * q + mQ
            BigInteger m = h.Multiply(q).Add(mQ);

            // defence against Arjen Lenstra�s CRT attack
            BigInteger check = m.ModPow(crt.PublicExponent, crt.Modulus);
            if (!check.Equals(input))
                throw new InvalidOperationException("RSA engine faulty decryption/signing detected");

            return m;
        }

        private void CheckInitialised()
        {
            if (m_key == null)
                throw new InvalidOperationException("RSA engine not initialised");
        }
    }
}
