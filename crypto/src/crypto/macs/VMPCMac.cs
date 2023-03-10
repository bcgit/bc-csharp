using System;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Macs
{
	public class VmpcMac
		: IMac
	{
		private byte g;

		private byte n = 0;
		private byte[] P = null;
		private byte s = 0;

		private readonly byte[] T = new byte[32];
		private byte[] workingIV;

		private byte[] workingKey;

		private byte x1, x2, x3, x4;

		public virtual int DoFinal(byte[] output, int outOff)
		{
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
			return DoFinal(output.AsSpan(outOff));
#else
			// Execute the Post-Processing Phase
			for (int r = 1; r < 25; r++)
			{
				s = P[(s + P[n & 0xFF]) & 0xFF];

				x4 = P[(x4 + x3 + r) & 0xFF];
				x3 = P[(x3 + x2 + r) & 0xFF];
				x2 = P[(x2 + x1 + r) & 0xFF];
				x1 = P[(x1 + s + r) & 0xFF];
				T[g & 0x1F] = (byte)(T[g & 0x1F] ^ x1);
				T[(g + 1) & 0x1F] = (byte)(T[(g + 1) & 0x1F] ^ x2);
				T[(g + 2) & 0x1F] = (byte)(T[(g + 2) & 0x1F] ^ x3);
				T[(g + 3) & 0x1F] = (byte)(T[(g + 3) & 0x1F] ^ x4);
				g = (byte)((g + 4) & 0x1F);

				byte temp = P[n & 0xFF];
				P[n & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
				n = (byte)((n + 1) & 0xFF);
			}

			// Input T to the IV-phase of the VMPC KSA
			for (int m = 0; m < 768; m++)
			{
				s = P[(s + P[m & 0xFF] + T[m & 0x1F]) & 0xFF];
				byte temp = P[m & 0xFF];
				P[m & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
			}

			// Store 20 new outputs of the VMPC Stream Cipher input table M
			byte[] M = new byte[20];
			for (int i = 0; i < 20; i++)
			{
				s = P[(s + P[i & 0xFF]) & 0xFF];
				M[i] = P[(P[(P[s & 0xFF]) & 0xFF] + 1) & 0xFF];

				byte temp = P[i & 0xFF];
				P[i & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
			}

			Array.Copy(M, 0, output, outOff, M.Length);
			Reset();

			return M.Length;
#endif
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		public virtual int DoFinal(Span<byte> output)
        {
			// Execute the Post-Processing Phase
			for (int r = 1; r < 25; r++)
			{
				s = P[(s + P[n & 0xFF]) & 0xFF];

				x4 = P[(x4 + x3 + r) & 0xFF];
				x3 = P[(x3 + x2 + r) & 0xFF];
				x2 = P[(x2 + x1 + r) & 0xFF];
				x1 = P[(x1 + s + r) & 0xFF];
				T[g & 0x1F] = (byte)(T[g & 0x1F] ^ x1);
				T[(g + 1) & 0x1F] = (byte)(T[(g + 1) & 0x1F] ^ x2);
				T[(g + 2) & 0x1F] = (byte)(T[(g + 2) & 0x1F] ^ x3);
				T[(g + 3) & 0x1F] = (byte)(T[(g + 3) & 0x1F] ^ x4);
				g = (byte)((g + 4) & 0x1F);

				byte temp = P[n & 0xFF];
				P[n & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
				n = (byte)((n + 1) & 0xFF);
			}

			// Input T to the IV-phase of the VMPC KSA
			for (int m = 0; m < 768; m++)
			{
				s = P[(s + P[m & 0xFF] + T[m & 0x1F]) & 0xFF];
				byte temp = P[m & 0xFF];
				P[m & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
			}

			// Store 20 new outputs of the VMPC Stream Cipher input table M
			byte[] M = new byte[20];
			for (int i = 0; i < 20; i++)
			{
				s = P[(s + P[i & 0xFF]) & 0xFF];
				M[i] = P[(P[(P[s & 0xFF]) & 0xFF] + 1) & 0xFF];

				byte temp = P[i & 0xFF];
				P[i & 0xFF] = P[s & 0xFF];
				P[s & 0xFF] = temp;
			}

			M.CopyTo(output);
			Reset();

			return M.Length;
		}
#endif

		public virtual string AlgorithmName => "VMPC-MAC";

		public virtual int GetMacSize() => 20;

		public virtual void Init(ICipherParameters parameters)
		{
			if (!(parameters is ParametersWithIV ivParams))
				throw new ArgumentException("VMPC-MAC Init parameters must include an IV", "parameters");
			if (!(ivParams.Parameters is KeyParameter key))
				throw new ArgumentException("VMPC-MAC Init parameters must include a key", "parameters");

            int keyLength = key.KeyLength;
            if (keyLength < 16 || keyLength > 64)
                throw new ArgumentException("VMPC requires 16 to 64 bytes of key");

            int ivLength = ivParams.IVLength;
            if (ivLength < 16 || ivLength > 64)
                throw new ArgumentException("VMPC requires 16 to 64 bytes of IV");

            this.workingKey = key.GetKey();
            this.workingIV = ivParams.GetIV();

			Reset();
		}

		private void InitKey(byte[] keyBytes, byte[] ivBytes)
		{
            n = 0;
            s = 0;
			P = new byte[256];
			for (int i = 0; i < 256; i++)
			{
				P[i] = (byte)i;
			}
			VmpcEngine.KsaRound(P, ref s, keyBytes);
            VmpcEngine.KsaRound(P, ref s, ivBytes);
		}

		public virtual void Reset()
		{
			InitKey(this.workingKey, this.workingIV);
			g = x1 = x2 = x3 = x4 = n = 0;
			Array.Clear(T, 0, T.Length);
		}

		public virtual void Update(byte input)
		{
            byte pn = P[n];
            s = P[(s + pn) & 0xFF];
            byte ps = P[s];
            byte c = (byte)(input ^ P[(P[ps] + 1) & 0xFF]);

            x4 = P[(x4 + x3) & 0xFF];
            x3 = P[(x3 + x2) & 0xFF];
            x2 = P[(x2 + x1) & 0xFF];
            x1 = P[(x1 + s + c) & 0xFF];
            T[g & 0x1F] = (byte)(T[g & 0x1F] ^ x1);
            T[(g + 1) & 0x1F] = (byte)(T[(g + 1) & 0x1F] ^ x2);
            T[(g + 2) & 0x1F] = (byte)(T[(g + 2) & 0x1F] ^ x3);
            T[(g + 3) & 0x1F] = (byte)(T[(g + 3) & 0x1F] ^ x4);
            g = (byte)((g + 4) & 0x1F);

            P[n] = ps;
            P[s] = pn;
            n = (byte)(n + 1);
        }

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen)
		{
			Check.DataLength(input, inOff, inLen, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
			BlockUpdate(input.AsSpan(inOff, inLen));
#else
			for (int i = 0; i < inLen; i++)
			{
                byte pn = P[n];
                s = P[(s + pn) & 0xFF];
                byte ps = P[s];
                byte c = (byte)(input[inOff + i] ^ P[(P[ps] + 1) & 0xFF]);

                x4 = P[(x4 + x3) & 0xFF];
                x3 = P[(x3 + x2) & 0xFF];
                x2 = P[(x2 + x1) & 0xFF];
                x1 = P[(x1 + s + c) & 0xFF];
                T[g & 0x1F] = (byte)(T[g & 0x1F] ^ x1);
                T[(g + 1) & 0x1F] = (byte)(T[(g + 1) & 0x1F] ^ x2);
                T[(g + 2) & 0x1F] = (byte)(T[(g + 2) & 0x1F] ^ x3);
                T[(g + 3) & 0x1F] = (byte)(T[(g + 3) & 0x1F] ^ x4);
                g = (byte)((g + 4) & 0x1F);

                P[n] = ps;
                P[s] = pn;
                n = (byte)(n + 1);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
			for (int i = 0; i < input.Length; i++)
			{
                byte pn = P[n];
                s = P[(s + pn) & 0xFF];
                byte ps = P[s];
                byte c = (byte)(input[i] ^ P[(P[ps] + 1) & 0xFF]);

                x4 = P[(x4 + x3) & 0xFF];
                x3 = P[(x3 + x2) & 0xFF];
                x2 = P[(x2 + x1) & 0xFF];
                x1 = P[(x1 + s + c) & 0xFF];
                T[g & 0x1F] = (byte)(T[g & 0x1F] ^ x1);
                T[(g + 1) & 0x1F] = (byte)(T[(g + 1) & 0x1F] ^ x2);
                T[(g + 2) & 0x1F] = (byte)(T[(g + 2) & 0x1F] ^ x3);
                T[(g + 3) & 0x1F] = (byte)(T[(g + 3) & 0x1F] ^ x4);
                g = (byte)((g + 4) & 0x1F);

                P[n] = ps;
                P[s] = pn;
                n = (byte)(n + 1);
            }
        }
#endif
    }
}
