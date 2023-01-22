#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Engines
{
    using Aes = System.Runtime.Intrinsics.X86.Aes;
    using Sse2 = System.Runtime.Intrinsics.X86.Sse2;

    public sealed class AesEngine_X86 : IBlockCipher
    {
        public static bool IsSupported => Aes.IsSupported;

        public AesEngine_X86()
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(AesEngine_X86));
        }

        public string AlgorithmName => "AES";

        public int GetBlockSize() => 16;

        private AesEncoderDecoder _implementation;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (parameters is not KeyParameter keyParameter)
            {
                ArgumentNullException.ThrowIfNull(parameters, nameof(parameters));
                throw new ArgumentException("invalid type: " + parameters.GetType(), nameof(parameters));
            }

            Vector128<byte>[] roundKeys = CreateRoundKeys(keyParameter.GetKey(), forEncryption);
            _implementation = AesEncoderDecoder.Init(forEncryption, roundKeys);
        }

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            Check.DataLength(inBuf, inOff, 16);
            Check.OutputLength(outBuf, outOff, 16);

            Vector128<byte> state = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(inBuf), inOff));

            _implementation.ProcessRounds(ref state);

            Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(outBuf), outOff)) = state;

            return 16;
        }

        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.DataLength(input, 16);
            Check.OutputLength(output, 16);

            Vector128<byte> state = Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(input));

            _implementation.ProcessRounds(ref state);

            Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(output)) = state;

            return 16;;
        }

        private static Vector128<byte>[] CreateRoundKeys(byte[] key, bool forEncryption)
        {
            Vector128<byte>[] K = key.Length switch
            {
                16 => KeyLength16(key),
                24 => KeyLength24(key),
                32 => KeyLength32(key),
                _ => throw new ArgumentException("Key length not 128/192/256 bits.")
            };

            if (!forEncryption)
            {
                for (int i = 1, last = K.Length - 1; i < last; ++i)
                {
                    K[i] = Aes.InverseMixColumns(K[i]);
                }

                Array.Reverse(K);
            }

            return K;

            static Vector128<byte>[] KeyLength16(byte[] key)
            {
                ReadOnlySpan<byte> rcon = stackalloc byte[] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

                Vector128<byte> s = MemoryMarshal.Read<Vector128<byte>>(key.AsSpan(0, 16));
                Vector128<byte>[] K = new Vector128<byte>[11];
                K[0] = s;

                for (int round = 0; round < 10;)
                {
                    Vector128<byte> t = Aes.KeygenAssist(s, rcon[round++]);
                    t = Sse2.Shuffle(t.AsInt32(), 0xFF).AsByte();
                    s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));
                    s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 4));
                    s = Sse2.Xor(s, t);
                    K[round] = s;
                }

                return K;
            }

            static Vector128<byte>[] KeyLength24(byte[] key)
            {
                Vector128<byte> s1 = MemoryMarshal.Read<Vector128<byte>>(key.AsSpan(0, 16));
                Vector128<byte> s2 = MemoryMarshal.Read<Vector64<byte>>(key.AsSpan(16, 8)).ToVector128();
                Vector128<byte>[] K = new Vector128<byte>[13];
                K[0] = s1;

                byte rcon = 0x01;
                for (int round = 0; ;)
                {
                    Vector128<byte> t1 = Aes.KeygenAssist(s2, rcon); rcon <<= 1;
                    t1 = Sse2.Shuffle(t1.AsInt32(), 0x55).AsByte();

                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                    s1 = Sse2.Xor(s1, t1);

                    K[++round] = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s1, 8));

                    Vector128<byte> s3 = Sse2.Xor(s2, Sse2.ShiftRightLogical128BitLane(s1, 12));
                    s3 = Sse2.Xor(s3, Sse2.ShiftLeftLogical128BitLane(s3, 4));

                    K[++round] = Sse2.Xor(
                        Sse2.ShiftRightLogical128BitLane(s1, 8),
                        Sse2.ShiftLeftLogical128BitLane(s3, 8));

                    Vector128<byte> t2 = Aes.KeygenAssist(s3, rcon); rcon <<= 1;
                    t2 = Sse2.Shuffle(t2.AsInt32(), 0x55).AsByte();

                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                    s1 = Sse2.Xor(s1, t2);

                    K[++round] = s1;

                    if (round == 12)
                        break;

                    s2 = Sse2.Xor(s3, Sse2.ShiftRightLogical128BitLane(s1, 12));
                    s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 4));
                    s2 = s2.WithUpper(Vector64<byte>.Zero);
                }

                return K;
            }

            static Vector128<byte>[] KeyLength32(byte[] key)
            {
                Vector128<byte> s1 = MemoryMarshal.Read<Vector128<byte>>(key.AsSpan(0, 16));
                Vector128<byte> s2 = MemoryMarshal.Read<Vector128<byte>>(key.AsSpan(16, 16));
                Vector128<byte>[] K = new Vector128<byte>[15];
                K[0] = s1;
                K[1] = s2;

                byte rcon = 0x01;
                for (int round = 1; ;)
                {
                    Vector128<byte> t1 = Aes.KeygenAssist(s2, rcon); rcon <<= 1;
                    t1 = Sse2.Shuffle(t1.AsInt32(), 0xFF).AsByte();
                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                    s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                    s1 = Sse2.Xor(s1, t1);
                    K[++round] = s1;

                    if (round == 14)
                        break;

                    Vector128<byte> t2 = Aes.KeygenAssist(s1, 0x00);
                    t2 = Sse2.Shuffle(t2.AsInt32(), 0xAA).AsByte();
                    s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 8));
                    s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 4));
                    s2 = Sse2.Xor(s2, t2);
                    K[++round] = s2;
                }

                return K;
            }
        }

        private abstract class AesEncoderDecoder
        {
            protected readonly Vector128<byte>[] _roundKeys;

            public AesEncoderDecoder(Vector128<byte>[] roundKeys)
            {
                _roundKeys = roundKeys;
            }

            public static AesEncoderDecoder Init(bool forEncryption, Vector128<byte>[] roundKeys)
            {
                if (roundKeys.Length == 11)
                {
                    return forEncryption ? new Encode128(roundKeys) : new Decode128(roundKeys);
                }
                else if (roundKeys.Length == 13)
                {
                    return forEncryption ? new Encode192(roundKeys) : new Decode192(roundKeys);
                }
                else
                {
                    return forEncryption ? new Encode256(roundKeys) : new Decode256(roundKeys);
                }
            }

            public abstract void ProcessRounds(ref Vector128<byte> state);

            private sealed class Encode128 : AesEncoderDecoder
            {
                public Encode128(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[10];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Encrypt(state2, roundKeys[1]);
                    state2 = Aes.Encrypt(state2, roundKeys[2]);
                    state2 = Aes.Encrypt(state2, roundKeys[3]);
                    state2 = Aes.Encrypt(state2, roundKeys[4]);
                    state2 = Aes.Encrypt(state2, roundKeys[5]);
                    state2 = Aes.Encrypt(state2, roundKeys[6]);
                    state2 = Aes.Encrypt(state2, roundKeys[7]);
                    state2 = Aes.Encrypt(state2, roundKeys[8]);
                    state2 = Aes.Encrypt(state2, roundKeys[9]);
                    state2 = Aes.EncryptLast(state2, roundKeys[10]);
                    // Copy back to ref
                    state = state2;
                }
            }

            private sealed class Decode128 : AesEncoderDecoder
            {
                public Decode128(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[10];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Decrypt(state2, roundKeys[1]);
                    state2 = Aes.Decrypt(state2, roundKeys[2]);
                    state2 = Aes.Decrypt(state2, roundKeys[3]);
                    state2 = Aes.Decrypt(state2, roundKeys[4]);
                    state2 = Aes.Decrypt(state2, roundKeys[5]);
                    state2 = Aes.Decrypt(state2, roundKeys[6]);
                    state2 = Aes.Decrypt(state2, roundKeys[7]);
                    state2 = Aes.Decrypt(state2, roundKeys[8]);
                    state2 = Aes.Decrypt(state2, roundKeys[9]);
                    state2 = Aes.DecryptLast(state2, roundKeys[10]);
                    // Copy back to ref
                    state = state2;
                }
            }

            private sealed class Encode192 : AesEncoderDecoder
            {
                public Encode192(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[12];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Encrypt(state2, roundKeys[1]);
                    state2 = Aes.Encrypt(state2, roundKeys[2]);
                    state2 = Aes.Encrypt(state2, roundKeys[3]);
                    state2 = Aes.Encrypt(state2, roundKeys[4]);
                    state2 = Aes.Encrypt(state2, roundKeys[5]);
                    state2 = Aes.Encrypt(state2, roundKeys[6]);
                    state2 = Aes.Encrypt(state2, roundKeys[7]);
                    state2 = Aes.Encrypt(state2, roundKeys[8]);
                    state2 = Aes.Encrypt(state2, roundKeys[9]);
                    state2 = Aes.Encrypt(state2, roundKeys[10]);
                    state2 = Aes.Encrypt(state2, roundKeys[11]);
                    state2 = Aes.EncryptLast(state2, roundKeys[12]);
                    // Copy back to ref
                    state = state2;
                }
            }

            private sealed class Decode192 : AesEncoderDecoder
            {
                public Decode192(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[12];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Decrypt(state2, roundKeys[1]);
                    state2 = Aes.Decrypt(state2, roundKeys[2]);
                    state2 = Aes.Decrypt(state2, roundKeys[3]);
                    state2 = Aes.Decrypt(state2, roundKeys[4]);
                    state2 = Aes.Decrypt(state2, roundKeys[5]);
                    state2 = Aes.Decrypt(state2, roundKeys[6]);
                    state2 = Aes.Decrypt(state2, roundKeys[7]);
                    state2 = Aes.Decrypt(state2, roundKeys[8]);
                    state2 = Aes.Decrypt(state2, roundKeys[9]);
                    state2 = Aes.Decrypt(state2, roundKeys[10]);
                    state2 = Aes.Decrypt(state2, roundKeys[11]);
                    state2 = Aes.DecryptLast(state2, roundKeys[12]);
                    // Copy back to ref
                    state = state2;
                }
            }

            private sealed class Encode256 : AesEncoderDecoder
            {
                public Encode256(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[14];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Encrypt(state2, roundKeys[1]);
                    state2 = Aes.Encrypt(state2, roundKeys[2]);
                    state2 = Aes.Encrypt(state2, roundKeys[3]);
                    state2 = Aes.Encrypt(state2, roundKeys[4]);
                    state2 = Aes.Encrypt(state2, roundKeys[5]);
                    state2 = Aes.Encrypt(state2, roundKeys[6]);
                    state2 = Aes.Encrypt(state2, roundKeys[7]);
                    state2 = Aes.Encrypt(state2, roundKeys[8]);
                    state2 = Aes.Encrypt(state2, roundKeys[9]);
                    state2 = Aes.Encrypt(state2, roundKeys[10]);
                    state2 = Aes.Encrypt(state2, roundKeys[11]);
                    state2 = Aes.Encrypt(state2, roundKeys[12]);
                    state2 = Aes.Encrypt(state2, roundKeys[13]);
                    state2 = Aes.EncryptLast(state2, roundKeys[14]);
                    // Copy back to ref
                    state = state2;
                }
            }

            private sealed class Decode256 : AesEncoderDecoder
            {
                public Decode256(Vector128<byte>[] roundKeys) : base(roundKeys) { }

                public override void ProcessRounds(ref Vector128<byte> state)
                {
                    // Take local refence to array so Jit can reason length doesn't change in method
                    Vector128<byte>[] roundKeys = _roundKeys;
                    {
                        // Get the Jit to bounds check once rather than each increasing array access
                        Vector128<byte> temp = roundKeys[14];
                    }

                    // Operate on non-ref local so it remains in register rather than operating on memory
                    Vector128<byte> state2 = Sse2.Xor(state, roundKeys[0]);
                    state2 = Aes.Decrypt(state2, roundKeys[1]);
                    state2 = Aes.Decrypt(state2, roundKeys[2]);
                    state2 = Aes.Decrypt(state2, roundKeys[3]);
                    state2 = Aes.Decrypt(state2, roundKeys[4]);
                    state2 = Aes.Decrypt(state2, roundKeys[5]);
                    state2 = Aes.Decrypt(state2, roundKeys[6]);
                    state2 = Aes.Decrypt(state2, roundKeys[7]);
                    state2 = Aes.Decrypt(state2, roundKeys[8]);
                    state2 = Aes.Decrypt(state2, roundKeys[9]);
                    state2 = Aes.Decrypt(state2, roundKeys[10]);
                    state2 = Aes.Decrypt(state2, roundKeys[11]);
                    state2 = Aes.Decrypt(state2, roundKeys[12]);
                    state2 = Aes.Decrypt(state2, roundKeys[13]);
                    state2 = Aes.DecryptLast(state2, roundKeys[14]);
                    // Copy back to ref
                    state = state2;
                }
            }
        }

        private static class Check
        {
            public static void DataLength(byte[] buf, int off, int len)
            {
                if (off > (buf.Length - len)) ThrowDataLengthException();
            }

            public static void DataLength(ReadOnlySpan<byte> buf, int len)
            {
                if (buf.Length < len) ThrowDataLengthException();
            }

            public static void OutputLength(byte[] buf, int off, int len)
            {
                if (off > (buf.Length - len)) ThrowOutputLengthException();
            }

            public static void OutputLength(Span<byte> buf, int len)
            {
                if (buf.Length < len) ThrowOutputLengthException();
            }

            private static void ThrowDataLengthException() => throw new DataLengthException("input buffer too short");
            private static void ThrowOutputLengthException() => throw new OutputLengthException("output buffer too short");
        }
    }

}
#endif
