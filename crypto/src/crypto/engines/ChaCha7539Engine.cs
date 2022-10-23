using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>
    /// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
    /// </summary>
    public class ChaCha7539Engine
        : Salsa20Engine
    {
        /// <summary>
        /// Creates a 20 rounds ChaCha engine.
        /// </summary>
        public ChaCha7539Engine()
            : base()
        {
        }

        public override string AlgorithmName
        {
            get { return "ChaCha7539"; }
        }

        protected override int NonceSize
        {
            get { return 12; }
        }

        protected override void AdvanceCounter()
        {
            if (++engineState[12] == 0)
                throw new InvalidOperationException("attempt to increase counter past 2^32.");
        }

        protected override void ResetCounter()
        {
            engineState[12] = 0;
        }

        protected override void SetKey(byte[] keyBytes, byte[] ivBytes)
        {
            if (keyBytes != null)
            {
                if (keyBytes.Length != 32)
                    throw new ArgumentException(AlgorithmName + " requires 256 bit key");

                PackTauOrSigma(keyBytes.Length, engineState, 0);

                // Key
                Pack.LE_To_UInt32(keyBytes, 0, engineState, 4, 8);
            }

            // IV
            Pack.LE_To_UInt32(ivBytes, 0, engineState, 13, 3);
        }

        protected override void GenerateKeyStream(byte[] output)
        {
            ChaChaEngine.ChachaCore(rounds, engineState, output);
        }

		internal void DoFinal(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
		{
			if (!initialised)
				throw new InvalidOperationException(AlgorithmName + " not initialised");
			if (index != 0)
				throw new InvalidOperationException(AlgorithmName + " not in block-aligned state");

			Check.DataLength(inBuf, inOff, inLen, "input buffer too short");
			Check.OutputLength(outBuf, outOff, inLen, "output buffer too short");

			while (inLen >= 128)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessBlocks2(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
#else
				ProcessBlocks2(inBuf, inOff, outBuf, outOff);
#endif
                inOff += 128;
				inLen -= 128;
				outOff += 128;
			}

			if (inLen >= 64)
			{
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ImplProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
#else
                ImplProcessBlock(inBuf, inOff, outBuf, outOff);
#endif
                inOff += 64;
				inLen -= 64;
				outOff += 64;
			}

			if (inLen > 0)
            {
                GenerateKeyStream(keyStream);
                AdvanceCounter();

				for (int i = 0; i < inLen; ++i)
                {
                    outBuf[outOff + i] = (byte)(inBuf[i + inOff] ^ keyStream[i]);
                }
			}

			engineState[12] = 0;

			// TODO Prevent re-use if encrypting
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");
            if (LimitExceeded(64U))
                throw new MaxBytesExceededException("2^38 byte limit per IV would be exceeded; Change IV");

            Debug.Assert(index == 0);

            ImplProcessBlock(input, output);
        }

        internal void ProcessBlocks2(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");
            if (LimitExceeded(128U))
                throw new MaxBytesExceededException("2^38 byte limit per IV would be exceeded; Change IV");

            Debug.Assert(index == 0);

#if NETCOREAPP3_0_OR_GREATER
            if (Avx2.IsSupported)
            {
                ImplProcessBlocks2_X86_Avx2(rounds, engineState, input, output);
                return;
            }

            if (Sse2.IsSupported)
            {
                ImplProcessBlocks2_X86_Sse2(rounds, engineState, input, output);
                return;
            }
#endif

            {
				ImplProcessBlock(input, output);
				ImplProcessBlock(input[64..], output[64..]);
			}
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void ImplProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            ChaChaEngine.ChachaCore(rounds, engineState, keyStream);
            AdvanceCounter();

            for (int i = 0; i < 64; ++i)
            {
                output[i] = (byte)(keyStream[i] ^ input[i]);
            }
        }
#else
		internal void ProcessBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");
            if (LimitExceeded(64U))
                throw new MaxBytesExceededException("2^38 byte limit per IV would be exceeded; Change IV");

            Debug.Assert(index == 0);

			ImplProcessBlock(inBytes, inOff, outBytes, outOff);
        }

        internal void ProcessBlocks2(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            if (!initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");
            if (LimitExceeded(128U))
                throw new MaxBytesExceededException("2^38 byte limit per IV would be exceeded; Change IV");

            Debug.Assert(index == 0);

            {
				ImplProcessBlock(inBytes, inOff, outBytes, outOff);
				ImplProcessBlock(inBytes, inOff + 64, outBytes, outOff + 64);
			}
		}

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
		internal void ImplProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
			ChaChaEngine.ChachaCore(rounds, engineState, keyStream);
			AdvanceCounter();

			for (int i = 0; i < 64; ++i)
			{
				outBuf[outOff + i] = (byte)(keyStream[i] ^ inBuf[inOff + i]);
			}
		}
#endif

#if NETCOREAPP3_0_OR_GREATER
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void ImplProcessBlocks2_X86_Avx2(int rounds, uint[] state, ReadOnlySpan<byte> input,
			Span<byte> output)
		{
			if (!Avx2.IsSupported)
				throw new PlatformNotSupportedException();

			Debug.Assert(rounds % 2 == 0);
			Debug.Assert(state.Length >= 16);
			Debug.Assert(input.Length >= 128);
			Debug.Assert(output.Length >= 128);

			var t0 = Load128_UInt32(state.AsSpan());
			var t1 = Load128_UInt32(state.AsSpan(4));
			var t2 = Load128_UInt32(state.AsSpan(8));
			var t3 = Load128_UInt32(state.AsSpan(12));
			++state[12];
			var t4 = Load128_UInt32(state.AsSpan(12));
			++state[12];

			var x0 = Vector256.Create(t0, t0);
			var x1 = Vector256.Create(t1, t1);
			var x2 = Vector256.Create(t2, t2);
			var x3 = Vector256.Create(t3, t4);

			var v0 = x0;
			var v1 = x1;
			var v2 = x2;
			var v3 = x3;

			for (int i = rounds; i > 0; i -= 2)
			{
				v0 = Avx2.Add(v0, v1);
				v3 = Avx2.Xor(v3, v0);
				v3 = Avx2.Xor(Avx2.ShiftLeftLogical(v3, 16), Avx2.ShiftRightLogical(v3, 16));
				v2 = Avx2.Add(v2, v3);
				v1 = Avx2.Xor(v1, v2);
				v1 = Avx2.Xor(Avx2.ShiftLeftLogical(v1, 12), Avx2.ShiftRightLogical(v1, 20));
				v0 = Avx2.Add(v0, v1);
				v3 = Avx2.Xor(v3, v0);
				v3 = Avx2.Xor(Avx2.ShiftLeftLogical(v3, 8), Avx2.ShiftRightLogical(v3, 24));
				v2 = Avx2.Add(v2, v3);
				v1 = Avx2.Xor(v1, v2);
				v1 = Avx2.Xor(Avx2.ShiftLeftLogical(v1, 7), Avx2.ShiftRightLogical(v1, 25));

				v1 = Avx2.Shuffle(v1, 0x39);
				v2 = Avx2.Shuffle(v2, 0x4E);
				v3 = Avx2.Shuffle(v3, 0x93);

				v0 = Avx2.Add(v0, v1);
				v3 = Avx2.Xor(v3, v0);
				v3 = Avx2.Xor(Avx2.ShiftLeftLogical(v3, 16), Avx2.ShiftRightLogical(v3, 16));
				v2 = Avx2.Add(v2, v3);
				v1 = Avx2.Xor(v1, v2);
				v1 = Avx2.Xor(Avx2.ShiftLeftLogical(v1, 12), Avx2.ShiftRightLogical(v1, 20));
				v0 = Avx2.Add(v0, v1);
				v3 = Avx2.Xor(v3, v0);
				v3 = Avx2.Xor(Avx2.ShiftLeftLogical(v3, 8), Avx2.ShiftRightLogical(v3, 24));
				v2 = Avx2.Add(v2, v3);
				v1 = Avx2.Xor(v1, v2);
				v1 = Avx2.Xor(Avx2.ShiftLeftLogical(v1, 7), Avx2.ShiftRightLogical(v1, 25));

				v1 = Avx2.Shuffle(v1, 0x93);
				v2 = Avx2.Shuffle(v2, 0x4E);
				v3 = Avx2.Shuffle(v3, 0x39);
			}

			v0 = Avx2.Add(v0, x0);
			v1 = Avx2.Add(v1, x1);
			v2 = Avx2.Add(v2, x2);
			v3 = Avx2.Add(v3, x3);

			var n0 = Avx2.Permute2x128(v0, v1, 0x20).AsByte();
			var n1 = Avx2.Permute2x128(v2, v3, 0x20).AsByte();
			var n2 = Avx2.Permute2x128(v0, v1, 0x31).AsByte();
			var n3 = Avx2.Permute2x128(v2, v3, 0x31).AsByte();

			n0 = Avx2.Xor(n0, Load256_Byte(input));
			n1 = Avx2.Xor(n1, Load256_Byte(input[0x20..]));
			n2 = Avx2.Xor(n2, Load256_Byte(input[0x40..]));
			n3 = Avx2.Xor(n3, Load256_Byte(input[0x60..]));

			Store256_Byte(n0, output);
			Store256_Byte(n1, output[0x20..]);
			Store256_Byte(n2, output[0x40..]);
			Store256_Byte(n3, output[0x60..]);
		}

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void ImplProcessBlocks2_X86_Sse2(int rounds, uint[] state, ReadOnlySpan<byte> input,
			Span<byte> output)
		{
			if (!Sse2.IsSupported)
				throw new PlatformNotSupportedException();

			Debug.Assert(rounds % 2 == 0);
			Debug.Assert(state.Length >= 16);
			Debug.Assert(input.Length >= 128);
			Debug.Assert(output.Length >= 128);

			var x0 = Load128_UInt32(state.AsSpan());
			var x1 = Load128_UInt32(state.AsSpan(4));
			var x2 = Load128_UInt32(state.AsSpan(8));
			var x3 = Load128_UInt32(state.AsSpan(12));
			++state[12];

			var v0 = x0;
			var v1 = x1;
			var v2 = x2;
			var v3 = x3;

			for (int i = rounds; i > 0; i -= 2)
			{
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 16), Sse2.ShiftRightLogical(v3, 16));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 12), Sse2.ShiftRightLogical(v1, 20));
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 8), Sse2.ShiftRightLogical(v3, 24));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 7), Sse2.ShiftRightLogical(v1, 25));

				v1 = Sse2.Shuffle(v1, 0x39);
				v2 = Sse2.Shuffle(v2, 0x4E);
				v3 = Sse2.Shuffle(v3, 0x93);

				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 16), Sse2.ShiftRightLogical(v3, 16));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 12), Sse2.ShiftRightLogical(v1, 20));
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 8), Sse2.ShiftRightLogical(v3, 24));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 7), Sse2.ShiftRightLogical(v1, 25));

				v1 = Sse2.Shuffle(v1, 0x93);
				v2 = Sse2.Shuffle(v2, 0x4E);
				v3 = Sse2.Shuffle(v3, 0x39);
			}

			v0 = Sse2.Add(v0, x0);
			v1 = Sse2.Add(v1, x1);
			v2 = Sse2.Add(v2, x2);
			v3 = Sse2.Add(v3, x3);

			var n0 = Load128_Byte(input);
			var n1 = Load128_Byte(input[0x10..]);
			var n2 = Load128_Byte(input[0x20..]);
			var n3 = Load128_Byte(input[0x30..]);

			n0 = Sse2.Xor(n0, v0.AsByte());
			n1 = Sse2.Xor(n1, v1.AsByte());
			n2 = Sse2.Xor(n2, v2.AsByte());
			n3 = Sse2.Xor(n3, v3.AsByte());

			Store128_Byte(n0, output);
			Store128_Byte(n1, output[0x10..]);
			Store128_Byte(n2, output[0x20..]);
			Store128_Byte(n3, output[0x30..]);

			x3 = Load128_UInt32(state.AsSpan(12));
			++state[12];

			v0 = x0;
			v1 = x1;
			v2 = x2;
			v3 = x3;

			for (int i = rounds; i > 0; i -= 2)
			{
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 16), Sse2.ShiftRightLogical(v3, 16));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 12), Sse2.ShiftRightLogical(v1, 20));
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 8), Sse2.ShiftRightLogical(v3, 24));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 7), Sse2.ShiftRightLogical(v1, 25));

				v1 = Sse2.Shuffle(v1, 0x39);
				v2 = Sse2.Shuffle(v2, 0x4E);
				v3 = Sse2.Shuffle(v3, 0x93);

				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 16), Sse2.ShiftRightLogical(v3, 16));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 12), Sse2.ShiftRightLogical(v1, 20));
				v0 = Sse2.Add(v0, v1);
				v3 = Sse2.Xor(v3, v0);
				v3 = Sse2.Xor(Sse2.ShiftLeftLogical(v3, 8), Sse2.ShiftRightLogical(v3, 24));
				v2 = Sse2.Add(v2, v3);
				v1 = Sse2.Xor(v1, v2);
				v1 = Sse2.Xor(Sse2.ShiftLeftLogical(v1, 7), Sse2.ShiftRightLogical(v1, 25));

				v1 = Sse2.Shuffle(v1, 0x93);
				v2 = Sse2.Shuffle(v2, 0x4E);
				v3 = Sse2.Shuffle(v3, 0x39);
			}

			v0 = Sse2.Add(v0, x0);
			v1 = Sse2.Add(v1, x1);
			v2 = Sse2.Add(v2, x2);
			v3 = Sse2.Add(v3, x3);

			n0 = Load128_Byte(input[0x40..]);
			n1 = Load128_Byte(input[0x50..]);
			n2 = Load128_Byte(input[0x60..]);
			n3 = Load128_Byte(input[0x70..]);

			n0 = Sse2.Xor(n0, v0.AsByte());
			n1 = Sse2.Xor(n1, v1.AsByte());
			n2 = Sse2.Xor(n2, v2.AsByte());
			n3 = Sse2.Xor(n3, v3.AsByte());

			Store128_Byte(n0, output[0x40..]);
			Store128_Byte(n1, output[0x50..]);
			Store128_Byte(n2, output[0x60..]);
			Store128_Byte(n3, output[0x70..]);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector128<byte> Load128_Byte(ReadOnlySpan<byte> t)
		{
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
                return MemoryMarshal.Read<Vector128<byte>>(t);

            return Vector128.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[..8]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[8..])
            ).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector128<uint> Load128_UInt32(ReadOnlySpan<uint> t)
		{
			if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<uint>>() == 16)
                return MemoryMarshal.Read<Vector128<uint>>(MemoryMarshal.Cast<uint, byte>(t));

			return Vector128.Create(t[0], t[1], t[2], t[3]);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector256<byte> Load256_Byte(ReadOnlySpan<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector256<byte>>() == 32)
                return MemoryMarshal.Read<Vector256<byte>>(t);

            return Vector256.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[ 0.. 8]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[ 8..16]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[16..24]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[24..32])
            ).AsByte();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Store128_Byte(Vector128<byte> s, Span<byte> t)
		{
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
            {
                MemoryMarshal.Write(t, ref s);
                return;
            }

            var u = s.AsUInt64();
            BinaryPrimitives.WriteUInt64LittleEndian(t[..8], u.GetElement(0));
            BinaryPrimitives.WriteUInt64LittleEndian(t[8..], u.GetElement(1));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Store256_Byte(Vector256<byte> s, Span<byte> t)
		{
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector256<byte>>() == 32)
			{
                MemoryMarshal.Write(t, ref s);
				return;
			}

			var u = s.AsUInt64();
            BinaryPrimitives.WriteUInt64LittleEndian(t[ 0.. 8], u.GetElement(0));
            BinaryPrimitives.WriteUInt64LittleEndian(t[ 8..16], u.GetElement(1));
            BinaryPrimitives.WriteUInt64LittleEndian(t[16..24], u.GetElement(2));
            BinaryPrimitives.WriteUInt64LittleEndian(t[24..32], u.GetElement(3));
		}
#endif
	}
}
