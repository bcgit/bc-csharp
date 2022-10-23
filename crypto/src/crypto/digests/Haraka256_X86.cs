#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace Org.BouncyCastle.Crypto.Digests
{
    using Aes = System.Runtime.Intrinsics.X86.Aes;
    using Sse2 = System.Runtime.Intrinsics.X86.Sse2;

    public static class Haraka256_X86
    {
        public static bool IsSupported => Aes.IsSupported;

        public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(Haraka256_X86));

            var s0 = Load128(input[  ..16]);
            var s1 = Load128(input[16..32]);

            ImplRounds(ref s0, ref s1, Haraka512_X86.DefaultRoundConstants.AsSpan(0, 20));

            s0 = Sse2.Xor(s0, Load128(input[  ..16]));
            s1 = Sse2.Xor(s1, Load128(input[16..32]));

            Store128(s0, output[  ..16]);
            Store128(s1, output[16..32]);
        }

        public static void Hash(ReadOnlySpan<byte> input, Span<byte> output,
            ReadOnlySpan<Vector128<byte>> roundConstants)
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(Haraka256_X86));

            var s0 = Load128(input[  ..16]);
            var s1 = Load128(input[16..32]);

            ImplRounds(ref s0, ref s1, roundConstants[..20]);

            s0 = Sse2.Xor(s0, Load128(input[  ..16]));
            s1 = Sse2.Xor(s1, Load128(input[16..32]));

            Store128(s0, output[  ..16]);
            Store128(s1, output[16..32]);
        }

        public static void Permute(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(Haraka256_X86));

            var s0 = Load128(input[  ..16]);
            var s1 = Load128(input[16..32]);

            ImplRounds(ref s0, ref s1, Haraka512_X86.DefaultRoundConstants.AsSpan(0, 20));

            Store128(s0, output[  ..16]);
            Store128(s1, output[16..32]);
        }

        public static void Permute(ReadOnlySpan<byte> input, Span<byte> output,
            ReadOnlySpan<Vector128<byte>> roundConstants)
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(Haraka256_X86));

            var s0 = Load128(input[  ..16]);
            var s1 = Load128(input[16..32]);

            ImplRounds(ref s0, ref s1, roundConstants[..20]);

            Store128(s0, output[  ..16]);
            Store128(s1, output[16..32]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ImplRounds(ref Vector128<byte> s0, ref Vector128<byte> s1, ReadOnlySpan<Vector128<byte>> rc)
        {
            ImplRound(ref s0, ref s1, rc[  .. 4]);
            ImplRound(ref s0, ref s1, rc[ 4.. 8]);
            ImplRound(ref s0, ref s1, rc[ 8..12]);
            ImplRound(ref s0, ref s1, rc[12..16]);
            ImplRound(ref s0, ref s1, rc[16..20]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ImplRound(ref Vector128<byte> s0, ref Vector128<byte> s1, ReadOnlySpan<Vector128<byte>> rc)
        {
            ImplAes(ref s0, ref s1, rc[..4]);
            ImplMix(ref s0, ref s1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ImplAes(ref Vector128<byte> s0, ref Vector128<byte> s1, ReadOnlySpan<Vector128<byte>> rc)
        {
            s0 = Aes.Encrypt(s0, rc[0]);
            s1 = Aes.Encrypt(s1, rc[1]);

            s0 = Aes.Encrypt(s0, rc[2]);
            s1 = Aes.Encrypt(s1, rc[3]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ImplMix(ref Vector128<byte> s0, ref Vector128<byte> s1)
        {
            Vector128<uint> t0 = s0.AsUInt32();
            Vector128<uint> t1 = s1.AsUInt32();
            s0 = Sse2.UnpackLow(t0, t1).AsByte();
            s1 = Sse2.UnpackHigh(t0, t1).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Load128(ReadOnlySpan<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
                return MemoryMarshal.Read<Vector128<byte>>(t);

            return Vector128.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[..8]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[8..])
            ).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Store128(Vector128<byte> s, Span<byte> t)
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
    }
}
#endif
