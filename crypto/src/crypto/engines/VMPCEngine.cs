using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Engines
{
    public class VmpcEngine
        : IStreamCipher
    {
        protected byte n = 0;
        protected byte[] P = null;
        protected byte s = 0;

        protected byte[] workingIV;
        protected byte[] workingKey;

        public virtual string AlgorithmName => "VMPC";

        /**
        * initialise a VMPC cipher.
        * 
        * @param forEncryption
        *    whether or not we are for encryption.
        * @param params
        *    the parameters required to set up the cipher.
        * @exception ArgumentException
        *    if the params argument is inappropriate.
        */
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (!(parameters is ParametersWithIV ivParams))
                throw new ArgumentException("VMPC Init parameters must include an IV");
            if (!(ivParams.Parameters is KeyParameter key))
                throw new ArgumentException("VMPC Init parameters must include a key");

            int keyLength = key.KeyLength;
            if (keyLength < 16 || keyLength > 64)
                throw new ArgumentException("VMPC requires 16 to 64 bytes of key");

            int ivLength = ivParams.IVLength;
            if (ivLength < 16 || ivLength > 64)
                throw new ArgumentException("VMPC requires 16 to 64 bytes of IV");

            this.workingKey = key.GetKey();
            this.workingIV = ivParams.GetIV();

            InitKey(this.workingKey, this.workingIV);
        }

        protected virtual void InitKey(byte[] keyBytes, byte[] ivBytes)
        {
            n = 0;
            s = 0;
            P = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                P[i] = (byte)i;
            }
            KsaRound(P, ref s, keyBytes);
            KsaRound(P, ref s, ivBytes);
        }

        public virtual void ProcessBytes(byte[]	input, int inOff, int len, byte[] output, int outOff)
        {
            Check.DataLength(input, inOff, len, "input buffer too short");
            Check.OutputLength(output, outOff, len, "output buffer too short");

            for (int i = 0; i < len; i++)
            {
                byte pn = P[n];
                s = P[(s + pn) & 0xFF];
                byte ps = P[s];
                output[outOff + i] = (byte)(input[inOff + i] ^ P[(P[ps] + 1) & 0xFF]);
                P[n] = ps;
                P[s] = pn;
                n = (byte)(n + 1);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.OutputLength(output, input.Length, "output buffer too short");

            for (int i = 0; i < input.Length; i++)
            {
                byte pn = P[n];
                s = P[(s + pn) & 0xFF];
                byte ps = P[s];
                output[i] = (byte)(input[i] ^ P[(P[ps] + 1) & 0xFF]);
                P[n] = ps;
                P[s] = pn;
                n = (byte)(n + 1);
            }
        }
#endif

        public virtual void Reset()
        {
            InitKey(this.workingKey, this.workingIV);
        }

        public virtual byte ReturnByte(byte input)
        {
            byte pn = P[n];
            s = P[(s + pn) & 0xFF];
            byte ps = P[s];
            byte output = (byte)(input ^ P[(P[ps] + 1) & 0xFF]);
            P[n] = ps;
            P[s] = pn;
            n = (byte)(n + 1);
            return output;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void KsaRound(byte[] P, ref byte S, ReadOnlySpan<byte> input)
#else
        internal static void KsaRound(byte[] P, ref byte S, byte[] input)
#endif
        {
            byte s = S;
            int modulus = input.Length, offset = 0;
            for (int m = 0; m < 768; m++)
            {
                byte pm = P[m & 0xFF];
                s = P[(s + pm + input[offset]) & 0xFF];
                int t = offset + 1 - modulus;
                offset = t + (modulus & (t >> 31));
                P[m & 0xFF] = P[s];
                P[s] = pm;
            }
            S = s;
        }
    }
}
