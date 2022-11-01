using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
	/// <summary>
	/// Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
	/// </summary>
	public class Salsa20Engine
		: IStreamCipher
	{
		public static readonly int DEFAULT_ROUNDS = 20;

		/** Constants */
		private const int StateSize = 16; // 16, 32 bit ints = 64 bytes

        private readonly static uint[] TAU_SIGMA = Pack.LE_To_UInt32(Strings.ToAsciiByteArray("expand 16-byte k" + "expand 32-byte k"), 0, 8);

        internal void PackTauOrSigma(int keyLength, uint[] state, int stateOffset)
        {
            int tsOff = (keyLength - 16) / 4;
            state[stateOffset] = TAU_SIGMA[tsOff];
            state[stateOffset + 1] = TAU_SIGMA[tsOff + 1];
            state[stateOffset + 2] = TAU_SIGMA[tsOff + 2];
            state[stateOffset + 3] = TAU_SIGMA[tsOff + 3];
        }

		protected int rounds;

		/*
		 * variables to hold the state of the engine
		 * during encryption and decryption
		 */
		internal int index = 0;
		internal uint[] engineState = new uint[StateSize]; // state
		internal uint[] x = new uint[StateSize]; // internal buffer
		internal byte[] keyStream = new byte[StateSize * 4]; // expanded state, 64 bytes
		internal bool initialised = false;

		/*
		 * internal counter
		 */
		private uint cW0, cW1, cW2;

		/// <summary>
		/// Creates a 20 round Salsa20 engine.
		/// </summary>
		public Salsa20Engine()
			: this(DEFAULT_ROUNDS)
		{
		}

		/// <summary>
		/// Creates a Salsa20 engine with a specific number of rounds.
		/// </summary>
		/// <param name="rounds">the number of rounds (must be an even number).</param>
		public Salsa20Engine(int rounds)
		{
			if (rounds <= 0 || (rounds & 1) != 0)
			{
				throw new ArgumentException("'rounds' must be a positive, even number");
			}

			this.rounds = rounds;
		}

        public virtual void Init(
			bool				forEncryption, 
			ICipherParameters	parameters)
		{
			/* 
			 * Salsa20 encryption and decryption is completely
			 * symmetrical, so the 'forEncryption' is 
			 * irrelevant. (Like 90% of stream ciphers)
			 */

			ParametersWithIV ivParams = parameters as ParametersWithIV;
			if (ivParams == null)
				throw new ArgumentException(AlgorithmName + " Init requires an IV", "parameters");

			byte[] iv = ivParams.GetIV();
			if (iv == null || iv.Length != NonceSize)
				throw new ArgumentException(AlgorithmName + " requires exactly " + NonceSize + " bytes of IV");

            ICipherParameters keyParam = ivParams.Parameters;
            if (keyParam == null)
            {
                if (!initialised)
                    throw new InvalidOperationException(AlgorithmName + " KeyParameter can not be null for first initialisation");

                SetKey(null, iv);
            }
            else if (keyParam is KeyParameter)
            {
                SetKey(((KeyParameter)keyParam).GetKey(), iv);
            }
            else
            {
                throw new ArgumentException(AlgorithmName + " Init parameters must contain a KeyParameter (or null for re-init)");
            }

            Reset();
			initialised = true;
		}

		protected virtual int NonceSize
		{
			get { return 8; }
		}

		public virtual string AlgorithmName
		{
			get
            { 
				string name = "Salsa20";
				if (rounds != DEFAULT_ROUNDS)
				{
					name += "/" + rounds;
				}
				return name;
			}
		}

        public virtual byte ReturnByte(
			byte input)
		{
			if (LimitExceeded())
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
			}

			if (index == 0)
			{
				GenerateKeyStream(keyStream);
				AdvanceCounter();
			}

			byte output = (byte)(keyStream[index] ^ input);
			index = (index + 1) & 63;

			return output;
		}

		protected virtual void AdvanceCounter()
		{
			if (++engineState[8] == 0)
			{
				++engineState[9];
			}
		}

        public virtual void ProcessBytes(
			byte[]	inBytes, 
			int		inOff, 
			int		len, 
			byte[]	outBytes, 
			int		outOff)
		{
			if (!initialised)
				throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.DataLength(inBytes, inOff, len, "input buffer too short");
            Check.OutputLength(outBytes, outOff, len, "output buffer too short");

            if (LimitExceeded((uint)len))
				throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");

            for (int i = 0; i < len; i++)
			{
				if (index == 0)
				{
					GenerateKeyStream(keyStream);
					AdvanceCounter();
				}
				outBytes[i+outOff] = (byte)(keyStream[index]^inBytes[i+inOff]);
				index = (index + 1) & 63;
			}
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.OutputLength(output, input.Length, "output buffer too short");

            if (LimitExceeded((uint)input.Length))
                throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");

            for (int i = 0; i < input.Length; i++)
            {
                if (index == 0)
                {
                    GenerateKeyStream(keyStream);
                    AdvanceCounter();
                }
                output[i] = (byte)(keyStream[index++] ^ input[i]);
                index &= 63;
            }
        }
#endif

        public virtual void Reset()
		{
			index = 0;
			ResetLimitCounter();
			ResetCounter();
		}

		protected virtual void ResetCounter()
		{
			engineState[8] = engineState[9] = 0;
		}

		protected virtual void SetKey(byte[] keyBytes, byte[] ivBytes)
		{
            if (keyBytes != null)
            {
                if ((keyBytes.Length != 16) && (keyBytes.Length != 32))
                    throw new ArgumentException(AlgorithmName + " requires 128 bit or 256 bit key");

                int tsOff = (keyBytes.Length - 16) / 4;
                engineState[0] = TAU_SIGMA[tsOff];
                engineState[5] = TAU_SIGMA[tsOff + 1];
                engineState[10] = TAU_SIGMA[tsOff + 2];
                engineState[15] = TAU_SIGMA[tsOff + 3];

                // Key
                Pack.LE_To_UInt32(keyBytes, 0, engineState, 1, 4);
                Pack.LE_To_UInt32(keyBytes, keyBytes.Length - 16, engineState, 11, 4);
            }

            // IV
            Pack.LE_To_UInt32(ivBytes, 0, engineState, 6, 2);
        }

        protected virtual void GenerateKeyStream(byte[] output)
		{
			SalsaCore(rounds, engineState, x);
			Pack.UInt32_To_LE(x, output, 0);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void SalsaCore(int rounds, ReadOnlySpan<uint> input, Span<uint> output)
		{
			if (input.Length < 16)
				throw new ArgumentException();
			if (output.Length < 16)
				throw new ArgumentException();
			if (rounds % 2 != 0)
				throw new ArgumentException("Number of rounds must be even");

#if NETCOREAPP3_0_OR_GREATER
            if (Sse41.IsSupported && BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<short>>() == 16)
			{
				Vector128<uint> b0, b1, b2, b3;
				{
                    var I = MemoryMarshal.AsBytes(input[..16]);
					var t0 = MemoryMarshal.Read<Vector128<short>>(I[0x00..0x10]);
                    var t1 = MemoryMarshal.Read<Vector128<short>>(I[0x10..0x20]);
                    var t2 = MemoryMarshal.Read<Vector128<short>>(I[0x20..0x30]);
                    var t3 = MemoryMarshal.Read<Vector128<short>>(I[0x30..0x40]);

                    var u0 = Sse41.Blend(t0, t2, 0xF0);
					var u1 = Sse41.Blend(t1, t3, 0xC3);
					var u2 = Sse41.Blend(t0, t2, 0x0F);
					var u3 = Sse41.Blend(t1, t3, 0x3C);

					b0 = Sse41.Blend(u0, u1, 0xCC).AsUInt32();
					b1 = Sse41.Blend(u0, u1, 0x33).AsUInt32();
					b2 = Sse41.Blend(u2, u3, 0xCC).AsUInt32();
					b3 = Sse41.Blend(u2, u3, 0x33).AsUInt32();
				}

                var c0 = b0;
                var c1 = b1;
                var c2 = b2;
                var c3 = b3;

                for (int i = rounds; i > 0; i -= 2)
				{
                    QuarterRound_Sse2(ref c0, ref c3, ref c2, ref c1);
                    QuarterRound_Sse2(ref c0, ref c1, ref c2, ref c3);
                }

                b0 = Sse2.Add(b0, c0);
                b1 = Sse2.Add(b1, c1);
                b2 = Sse2.Add(b2, c2);
                b3 = Sse2.Add(b3, c3);

                {
					var t0 = b0.AsUInt16();
                    var t1 = b1.AsUInt16();
                    var t2 = b2.AsUInt16();
                    var t3 = b3.AsUInt16();

					var u0 = Sse41.Blend(t0, t1, 0xCC);
					var u1 = Sse41.Blend(t0, t1, 0x33);
					var u2 = Sse41.Blend(t2, t3, 0xCC);
					var u3 = Sse41.Blend(t2, t3, 0x33);

					var v0 = Sse41.Blend(u0, u2, 0xF0);
                    var v1 = Sse41.Blend(u1, u3, 0xC3);
                    var v2 = Sse41.Blend(u0, u2, 0x0F);
                    var v3 = Sse41.Blend(u1, u3, 0x3C);

                    var X = MemoryMarshal.AsBytes(output[..16]);
                    MemoryMarshal.Write(X[0x00..0x10], ref v0);
                    MemoryMarshal.Write(X[0x10..0x20], ref v1);
                    MemoryMarshal.Write(X[0x20..0x30], ref v2);
                    MemoryMarshal.Write(X[0x30..0x40], ref v3);
                }
                return;
			}
#endif

			uint x00 = input[ 0];
			uint x01 = input[ 1];
			uint x02 = input[ 2];
			uint x03 = input[ 3];
			uint x04 = input[ 4];
			uint x05 = input[ 5];
			uint x06 = input[ 6];
			uint x07 = input[ 7];
			uint x08 = input[ 8];
			uint x09 = input[ 9];
			uint x10 = input[10];
			uint x11 = input[11];
			uint x12 = input[12];
			uint x13 = input[13];
			uint x14 = input[14];
			uint x15 = input[15];

			for (int i = rounds; i > 0; i -= 2)
			{
				QuarterRound(ref x00, ref x04, ref x08, ref x12);
                QuarterRound(ref x05, ref x09, ref x13, ref x01);
                QuarterRound(ref x10, ref x14, ref x02, ref x06);
                QuarterRound(ref x15, ref x03, ref x07, ref x11);

                QuarterRound(ref x00, ref x01, ref x02, ref x03);
                QuarterRound(ref x05, ref x06, ref x07, ref x04);
                QuarterRound(ref x10, ref x11, ref x08, ref x09);
                QuarterRound(ref x15, ref x12, ref x13, ref x14);
			}

			output[ 0] = x00 + input[ 0];
			output[ 1] = x01 + input[ 1];
			output[ 2] = x02 + input[ 2];
			output[ 3] = x03 + input[ 3];
			output[ 4] = x04 + input[ 4];
			output[ 5] = x05 + input[ 5];
			output[ 6] = x06 + input[ 6];
			output[ 7] = x07 + input[ 7];
			output[ 8] = x08 + input[ 8];
			output[ 9] = x09 + input[ 9];
			output[10] = x10 + input[10];
			output[11] = x11 + input[11];
			output[12] = x12 + input[12];
			output[13] = x13 + input[13];
			output[14] = x14 + input[14];
			output[15] = x15 + input[15];
		}
#else
		internal static void SalsaCore(int rounds, uint[] input, uint[] output)
		{
			if (input.Length < 16)
				throw new ArgumentException();
			if (output.Length < 16)
				throw new ArgumentException();
			if (rounds % 2 != 0)
				throw new ArgumentException("Number of rounds must be even");

			uint x00 = input[ 0];
			uint x01 = input[ 1];
			uint x02 = input[ 2];
			uint x03 = input[ 3];
			uint x04 = input[ 4];
			uint x05 = input[ 5];
			uint x06 = input[ 6];
			uint x07 = input[ 7];
			uint x08 = input[ 8];
			uint x09 = input[ 9];
			uint x10 = input[10];
			uint x11 = input[11];
			uint x12 = input[12];
			uint x13 = input[13];
			uint x14 = input[14];
			uint x15 = input[15];

			for (int i = rounds; i > 0; i -= 2)
			{
				QuarterRound(ref x00, ref x04, ref x08, ref x12);
                QuarterRound(ref x05, ref x09, ref x13, ref x01);
                QuarterRound(ref x10, ref x14, ref x02, ref x06);
                QuarterRound(ref x15, ref x03, ref x07, ref x11);

                QuarterRound(ref x00, ref x01, ref x02, ref x03);
                QuarterRound(ref x05, ref x06, ref x07, ref x04);
                QuarterRound(ref x10, ref x11, ref x08, ref x09);
                QuarterRound(ref x15, ref x12, ref x13, ref x14);
			}

			output[ 0] = x00 + input[ 0];
			output[ 1] = x01 + input[ 1];
			output[ 2] = x02 + input[ 2];
			output[ 3] = x03 + input[ 3];
			output[ 4] = x04 + input[ 4];
			output[ 5] = x05 + input[ 5];
			output[ 6] = x06 + input[ 6];
			output[ 7] = x07 + input[ 7];
			output[ 8] = x08 + input[ 8];
			output[ 9] = x09 + input[ 9];
			output[10] = x10 + input[10];
			output[11] = x11 + input[11];
			output[12] = x12 + input[12];
			output[13] = x13 + input[13];
			output[14] = x14 + input[14];
			output[15] = x15 + input[15];
		}
#endif

		internal void ResetLimitCounter()
		{
			cW0 = 0;
			cW1 = 0;
			cW2 = 0;
		}

		internal bool LimitExceeded()
		{
			if (++cW0 == 0)
			{
				if (++cW1 == 0)
				{
					return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
				}
			}

			return false;
		}

		/*
		 * this relies on the fact len will always be positive.
		 */
		internal bool LimitExceeded(
			uint len)
		{
			uint old = cW0;
			cW0 += len;
			if (cW0 < old)
			{
				if (++cW1 == 0)
				{
					return (++cW2 & 0x20) != 0;          // 2^(32 + 32 + 6)
				}
			}

			return false;
		}

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
		{
            b ^= Integers.RotateLeft(a + d,  7);
            c ^= Integers.RotateLeft(b + a,  9);
            d ^= Integers.RotateLeft(c + b, 13);
            a ^= Integers.RotateLeft(d + c, 18);
        }

#if NETCOREAPP3_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void QuarterRound_Sse2(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c,
			ref Vector128<uint> d)
        {
			b = Sse2.Xor(b, Rotate_Sse2(Sse2.Add(a, d), 7));
			c = Sse2.Xor(c, Rotate_Sse2(Sse2.Add(b, a), 9));
			d = Sse2.Xor(d, Rotate_Sse2(Sse2.Add(c, b), 13));
			a = Sse2.Xor(a, Rotate_Sse2(Sse2.Add(d, c), 18));

            b = Sse2.Shuffle(b, 0x93);
			c = Sse2.Shuffle(c, 0x4E);
			d = Sse2.Shuffle(d, 0x39);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Rotate_Sse2(Vector128<uint> x, byte sl)
        {
			byte sr = (byte)(32 - sl);
            return Sse2.Xor(Sse2.ShiftLeftLogical(x, sl), Sse2.ShiftRightLogical(x, sr));
        }
#endif
    }
}
