using System;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.InteropServices;
#endif
using System.Threading.Tasks;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class Argon2BytesGenerator
    {
        private const int Argon2BlockSize = 1024;
        private const int Argon2QwordsInBlock = Argon2BlockSize / 8;

        private const int Argon2AddressesInBlock = 128;

        private const int Argon2PrehashDigestLength = 64;
        private const int Argon2PrehashSeedLength = 72;

        private const int Argon2SyncPoints = 4;

        /* Minimum and maximum number of lanes (degree of parallelism) */
        private const int MinParallelism = 1;
        private const int MaxParallelism = (1 << 24) - 1;

        /* Minimum and maximum digest size in bytes */
        private const int MinOutlen = 4;

        /* Minimum and maximum number of passes */
        private const int MinIterations = 1;

        private readonly byte[] ZeroBytes = new byte[4];

        private readonly TaskFactory m_taskFactory;

        private Argon2Parameters parameters;
        private Block[] memory;
        private int segmentLength;
        private int laneLength;

        public Argon2BytesGenerator()
            : this(taskFactory: null)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="Argon2BytesGenerator"/> with an optional <see cref="TaskFactory"/>.
        /// </summary>
        /// <param name="taskFactory">
        /// The <see cref="TaskFactory"/> that (if not null) will be used for parallel execution when parallelism > 1.
        /// </param>
        public Argon2BytesGenerator(TaskFactory taskFactory)
        {
            m_taskFactory = taskFactory;
        }

        /**
         * Initialise the Argon2BytesGenerator from the parameters.
         *
         * @param parameters Argon2 configuration.
         */
        public void Init(Argon2Parameters parameters)
        {
            if (parameters.Version != Argon2Parameters.Version10 &&
                parameters.Version != Argon2Parameters.Version13)
            {
                throw new NotSupportedException("unknown Argon2 version");
            }
            if (parameters.Type != Argon2Parameters.Argon2d &&
                parameters.Type != Argon2Parameters.Argon2i &&
                parameters.Type != Argon2Parameters.Argon2id)
            {
                throw new NotSupportedException("unknown Argon2 type");
            }

            if (parameters.Parallelism < MinParallelism)
                throw new InvalidOperationException("parallelism must be at least " + MinParallelism);
            if (parameters.Parallelism > MaxParallelism)
                throw new InvalidOperationException("parallelism must be at most " + MaxParallelism);
            if (parameters.Iterations < MinIterations)
                throw new InvalidOperationException("iterations must be at least " + MinIterations);

            this.parameters = parameters;

            // 2. Align memory size
            // Minimum memoryBlocks = 8L blocks, where L is the number of lanes
            int memoryBlocks = System.Math.Max(parameters.Memory, 2 * Argon2SyncPoints * parameters.Parallelism);

            this.segmentLength = memoryBlocks / (Argon2SyncPoints * parameters.Parallelism);
            this.laneLength = segmentLength * Argon2SyncPoints;

            // Ensure that all segments have equal length
            memoryBlocks = parameters.Parallelism * laneLength;

            this.memory = new Block[memoryBlocks];

            for (int i = 0; i < memory.Length; i++)
            {
                memory[i] = new Block();
            }
        }

        public int GenerateBytes(char[] password, byte[] output) =>
            GenerateBytes(parameters.CharToByteConverter.Convert(password), output);

        public int GenerateBytes(char[] password, byte[] output, int outOff, int outLen) =>
            GenerateBytes(parameters.CharToByteConverter.Convert(password), output, outOff, outLen);

        public int GenerateBytes(byte[] password, byte[] output) => GenerateBytes(password, output, 0, output.Length);

        public int GenerateBytes(byte[] password, byte[] output, int outOff, int outLen)
        {
            if (outLen < MinOutlen)
                throw new InvalidOperationException("output length less than " + MinOutlen);

            byte[] tmpBlockBytes = new byte[Argon2BlockSize];

            Initialize(tmpBlockBytes, password, outLen);
            FillMemoryBlocks();
            Digest(tmpBlockBytes, output, outOff, outLen);

            Reset();

            return outLen;
        }

        // Clear memory.
        private void Reset()
        {
            // Reset memory.
            if (null != memory)
            {
                for (int i = 0; i < memory.Length; i++)
                {
                    Block b = memory[i];
                    b?.Clear();
                }
            }
        }

        private void FillMemoryBlocks()
        {
            for (int pass = 0; pass < parameters.Iterations; ++pass)
            {
                for (int slice = 0; slice < Argon2SyncPoints; ++slice)
                {
                    if (m_taskFactory == null || parameters.Parallelism <= 1)
                    {
                        for (int lane = 0; lane < parameters.Parallelism; ++lane)
                        {
                            var position = new Position(pass, slice, lane);
                            FillSegment(position);
                        }
                    }
                    else
                    {
                        Task[] tasks = new Task[parameters.Parallelism];

                        for (int lane = 0; lane < parameters.Parallelism; ++lane)
                        {
                            var position = new Position(pass, slice, lane);
                            tasks[lane] = m_taskFactory.StartNew(() => FillSegment(position));
                        }

                        Task.WaitAll(tasks);
                    }
                }
            }
        }

        private void FillSegment(Position position)
        {
            Block addressBlock = null, inputBlock = null;
            FillBlock filler = new FillBlock();

            bool dataIndependentAddressing = IsDataIndependentAddressing(position);
            int startingIndex = GetStartingIndex(position);
            int currentOffset = position.lane * laneLength + position.slice * segmentLength + startingIndex;
            int prevOffset = GetPrevOffset(currentOffset);

            if (dataIndependentAddressing)
            {
                addressBlock = filler.addressBlock.Clear();
                inputBlock = filler.inputBlock.Clear();

                InitAddressBlocks(filler, position, inputBlock, addressBlock);
            }

            bool withXor = IsWithXor(position);

            for (int index = startingIndex; index < segmentLength; ++index)
            {
                ulong pseudoRandom = GetPseudoRandom(
                    filler,
                    index,
                    addressBlock,
                    inputBlock,
                    prevOffset,
                    dataIndependentAddressing);

                int refLane = GetRefLane(position, pseudoRandom);
                int refColumn = GetRefColumn(position, index, pseudoRandom, refLane == position.lane);

                /* 2 Creating a new block */
                Block prevBlock = memory[prevOffset];
                Block refBlock = memory[((laneLength) * refLane + refColumn)];
                Block currentBlock = memory[currentOffset];

                if (withXor)
                {
                    filler.FillBlockWithXor(prevBlock, refBlock, currentBlock);
                }
                else
                {
                    filler.Fill(prevBlock, refBlock, currentBlock);
                }

                prevOffset = currentOffset;
                currentOffset++;
            }
        }

        private bool IsDataIndependentAddressing(Position position)
        {
            return (parameters.Type == Argon2Parameters.Argon2i) ||
                (parameters.Type == Argon2Parameters.Argon2id
                    && (position.pass == 0)
                    && (position.slice < Argon2SyncPoints / 2)
                );
        }

        private void InitAddressBlocks(FillBlock filler, Position position, Block inputBlock, Block addressBlock)
        {
            inputBlock.v[0] = (ulong)position.pass;
            inputBlock.v[1] = (ulong)position.lane;
            inputBlock.v[2] = (ulong)position.slice;
            inputBlock.v[3] = (ulong)memory.Length;
            inputBlock.v[4] = (ulong)parameters.Iterations;
            inputBlock.v[5] = (ulong)parameters.Type;

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Don't forget to generate the first block of addresses: */
                NextAddresses(filler, inputBlock, addressBlock);
            }
        }

        private bool IsWithXor(Position position)
        {
            return !(position.pass == 0 || parameters.Version == Argon2Parameters.Version10);
        }

        private int GetPrevOffset(int currentOffset)
        {
            if (currentOffset % laneLength == 0)
            {
                /* Last block in this lane */
                return currentOffset + laneLength - 1;
            }
            else
            {
                /* Previous block */
                return currentOffset - 1;
            }
        }

        private static int GetStartingIndex(Position position)
        {
            if ((position.pass == 0) && (position.slice == 0))
            {
                return 2; /* we have already generated the first two blocks */
            }
            else
            {
                return 0;
            }
        }

        private static void NextAddresses(FillBlock filler, Block inputBlock, Block addressBlock)
        {
            inputBlock.v[6]++;
            filler.Fill(inputBlock, addressBlock);
            filler.Fill(addressBlock, addressBlock);
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        private ulong GetPseudoRandom(
            FillBlock filler,
            int index,
            Block addressBlock,
            Block inputBlock,
            int prevOffset,
            bool dataIndependentAddressing)
        {
            if (dataIndependentAddressing)
            {
                int addressIndex = index % Argon2AddressesInBlock;
                if (addressIndex == 0)
                {
                    NextAddresses(filler, inputBlock, addressBlock);
                }
                return addressBlock.v[addressIndex];
            }
            else
            {
                return memory[prevOffset].v[0];
            }
        }

        private int GetRefLane(Position position, ulong pseudoRandom)
        {
            int refLane = (int)((long)(pseudoRandom >> 32) % parameters.Parallelism);

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Can not reference other lanes yet */
                refLane = position.lane;
            }
            return refLane;
        }

        private int GetRefColumn(Position position, int index, ulong pseudoRandom, bool sameLane)
        {
            ulong referenceAreaSize;
            ulong startPosition;

            if (position.pass == 0)
            {
                startPosition = 0;

                if (sameLane)
                {
                    /* The same lane => add current segment */
                    referenceAreaSize = (ulong)(position.slice * segmentLength + index - 1);
                }
                else
                {
                    /* pass == 0 && !sameLane => position.slice > 0*/
                    referenceAreaSize = (ulong)(position.slice * segmentLength + ((index == 0) ? (-1) : 0));
                }
            }
            else
            {
                startPosition = (ulong)(((position.slice + 1) * segmentLength) % laneLength);

                if (sameLane)
                {
                    referenceAreaSize = (ulong)(laneLength - segmentLength + index - 1);
                }
                else
                {
                    referenceAreaSize = (ulong)(laneLength - segmentLength + ((index == 0) ? (-1) : 0));
                }
            }

            ulong relativePosition = pseudoRandom & 0xFFFFFFFFUL;

            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >> 32);

            return (int)(startPosition + relativePosition) % laneLength;
        }

        private void Digest(byte[] tmpBlockBytes, byte[] output, int outOff, int outLen)
        {
            Block finalBlock = memory[laneLength - 1];

            /* XOR the last blocks */
            for (int i = 1; i < parameters.Parallelism; i++)
            {
                int lastBlockInLane = i * laneLength + (laneLength - 1);
                finalBlock.XorWith(memory[lastBlockInLane]);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            // If the platform supports it and is little endian, we can cast the array as a byte array directly
            if (BitConverter.IsLittleEndian)
            {
                Span<byte> accumulatorBytes = MemoryMarshal.AsBytes(finalBlock.v.AsSpan());
                Hash(accumulatorBytes, output.AsSpan(outOff, outLen));
            }
            else
#endif
            {
                finalBlock.ToBytes(tmpBlockBytes);

                Hash(tmpBlockBytes, output, outOff, outLen);
            }
        }

        /**
         * H' - hash - variable length hash function
         */
        private static void Hash(byte[] input, byte[] output, int outOff, int outLen)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Hash(input.AsSpan(), output.AsSpan(outOff, outLen));
        }

        private static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outLen = output.Length;
            int outOff = 0;
            Span<byte> outLenBytes = stackalloc byte[4];
#else
            byte[] outLenBytes = new byte[4];
#endif
            Pack.UInt32_To_LE((uint)outLen, outLenBytes);

            int blake2bLength = 64;

            if (outLen <= blake2bLength)
            {
                IDigest blake = new Blake2bDigest(outLen * 8);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                blake.BlockUpdate(outLenBytes);
                blake.BlockUpdate(input);
                blake.DoFinal(output);
#else
                blake.BlockUpdate(outLenBytes, 0, outLenBytes.Length);
                blake.BlockUpdate(input, 0, input.Length);
                blake.DoFinal(output, outOff);
#endif
            }
            else
            {
                int halfLen = blake2bLength / 2, outPos = outOff;

                IDigest digest = new Blake2bDigest(blake2bLength * 8);
                byte[] outBuffer = new byte[blake2bLength];

                /* V1 */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                digest.BlockUpdate(outLenBytes);
                digest.BlockUpdate(input);
                digest.DoFinal(outBuffer);
                outBuffer[0..halfLen].CopyTo(output);
#else
                digest.BlockUpdate(outLenBytes, 0, outLenBytes.Length);
                digest.BlockUpdate(input, 0, input.Length);
                digest.DoFinal(outBuffer, 0);
                Array.Copy(outBuffer, 0, output, outPos, halfLen);
#endif
                outPos += halfLen;

                int r = ((outLen + 31) / 32) - 2;

                for (int i = 2; i <= r; i++, outPos += halfLen)
                {
                    /* V2 to Vr */
                    digest.BlockUpdate(outBuffer, 0, outBuffer.Length);
                    digest.DoFinal(outBuffer, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    outBuffer[0..halfLen].CopyTo(output[outPos..]);
#else
                    Array.Copy(outBuffer, 0, output, outPos, halfLen);
#endif
                }

                int lastLength = outLen - 32 * r;

                /* Vr+1 */
                digest = new Blake2bDigest(lastLength * 8);

                digest.BlockUpdate(outBuffer, 0, outBuffer.Length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                digest.DoFinal(output[outPos..]);
#else
                digest.DoFinal(output, outPos);
#endif
            }
        }

#if NETCOREAPP3_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void GB(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
        {
            a += b + 2 * Mul32((uint)a, (uint)b);
            d = Longs.RotateRight(d ^ a, 32);
            c += d + 2 * Mul32((uint)c, (uint)d);
            b = Longs.RotateRight(b ^ c, 24);

            a += b + 2 * Mul32((uint)a, (uint)b);
            d = Longs.RotateRight(d ^ a, 16);
            c += d + 2 * Mul32((uint)c, (uint)d);
            b = Longs.RotateRight(b ^ c, 63);
        }

#if NETCOREAPP3_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static ulong Mul32(uint a, uint b) => (ulong)a * b;

        private void Initialize(byte[] tmpBlockBytes, byte[] password, int outputLength)
        {
            /*
             * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
             * -> 64 byte (Argon2PrehashDigestLength)
             */

            Blake2bDigest blake = new Blake2bDigest(Argon2PrehashDigestLength * 8);

            uint[] values = {
                (uint)parameters.Parallelism,
                (uint)outputLength,
                (uint)parameters.Memory,
                (uint)parameters.Iterations,
                (uint)parameters.Version,
                (uint)parameters.Type
            };

            Pack.UInt32_To_LE(values, tmpBlockBytes, 0);
            blake.BlockUpdate(tmpBlockBytes, 0, values.Length * 4);

            AddByteString(tmpBlockBytes, blake, password);
            AddByteString(tmpBlockBytes, blake, parameters.Salt);
            AddByteString(tmpBlockBytes, blake, parameters.Secret);
            AddByteString(tmpBlockBytes, blake, parameters.Additional);

            byte[] initialHashWithZeros = new byte[Argon2PrehashSeedLength];
            blake.DoFinal(initialHashWithZeros, 0);

            FillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
        }

        private void AddByteString(byte[] tmpBlockBytes, IDigest digest, byte[] octets)
        {
            if (null == octets)
            {
                digest.BlockUpdate(ZeroBytes, 0, 4);
                return;
            }

            Pack.UInt32_To_LE((uint)octets.Length, tmpBlockBytes, 0);
            digest.BlockUpdate(tmpBlockBytes, 0, 4);
            digest.BlockUpdate(octets, 0, octets.Length);
        }

        /**
         * (H0 || 0 || i) 72 byte -> 1024 byte
         * (H0 || 1 || i) 72 byte -> 1024 byte
         */
        private void FillFirstBlocks(byte[] tmpBlockBytes, byte[] initialHashWithZeros)
        {
            byte[] initialHashWithOnes = new byte[Argon2PrehashSeedLength];
            Array.Copy(initialHashWithZeros, 0, initialHashWithOnes, 0, Argon2PrehashDigestLength);
            initialHashWithOnes[Argon2PrehashDigestLength] = 1;

            for (int i = 0; i < parameters.Parallelism; i++)
            {
                Pack.UInt32_To_LE((uint)i, initialHashWithZeros, Argon2PrehashDigestLength + 4);
                Pack.UInt32_To_LE((uint)i, initialHashWithOnes, Argon2PrehashDigestLength + 4);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                if (BitConverter.IsLittleEndian)
                {
                    Span<byte> memorySpanZero = MemoryMarshal.AsBytes(memory[i * laneLength + 0].v.AsSpan());
                    Span<byte> memorySpanOne = MemoryMarshal.AsBytes(memory[i * laneLength + 1].v.AsSpan());

                    Hash(initialHashWithZeros, memorySpanZero);
                    Hash(initialHashWithOnes, memorySpanOne);
                }
                else
#endif
                {
                    Hash(initialHashWithZeros, tmpBlockBytes, 0, Argon2BlockSize);
                    memory[i * laneLength + 0].FromBytes(tmpBlockBytes);

                    Hash(initialHashWithOnes, tmpBlockBytes, 0, Argon2BlockSize);
                    memory[i * laneLength + 1].FromBytes(tmpBlockBytes);
                }
            }
        }

        private sealed class FillBlock
        {
            private readonly Block R = new Block();
            private readonly Block Z = new Block();

            internal readonly Block addressBlock = new Block();
            internal readonly Block inputBlock = new Block();

            internal void ApplyBlake()
            {
                // TODO Implement using intrinsics when supported (see e.g. Blake2b_X86)

                /*
                 * RFC 9106 3.5. [The block] is viewed as an 8x8 matrix of 16-byte registers R_0, R_1, ... , R_63.
                 * Then P is first applied to each row, and then to each column to get Z:
                 *
                 * ( Q_0,  Q_1,  Q_2, ... ,  Q_7) <- P( R_0,  R_1,  R_2, ... ,  R_7)
                 * ( Q_8,  Q_9, Q_10, ... , Q_15) <- P( R_8,  R_9, R_10, ... , R_15)
                 *                               ...
                 * (Q_56, Q_57, Q_58, ... , Q_63) <- P(R_56, R_57, R_58, ... , R_63)
                 * ( Z_0,  Z_8, Z_16, ... , Z_56) <- P( Q_0,  Q_8, Q_16, ... , Q_56)
                 * ( Z_1,  Z_9, Z_17, ... , Z_57) <- P( Q_1,  Q_9, Q_17, ... , Q_57)
                 *                               ...
                 * ( Z_7, Z_15, Z 23, ... , Z_63) <- P( Q_7, Q_15, Q_23, ... , Q_63)
                 */

                ulong[] v = Z.v;

                for (int i = 0; i < 128; i += 16)
                {
                    // Apply P to the row [i + 0 | i + 1], [i + 2 | i + 3], ..., [i + 14 | i + 15]

                    GB(ref v[i +  0], ref v[i +  4], ref v[i +  8], ref v[i + 12]);
                    GB(ref v[i +  1], ref v[i +  5], ref v[i +  9], ref v[i + 13]);
                    GB(ref v[i +  2], ref v[i +  6], ref v[i + 10], ref v[i + 14]);
                    GB(ref v[i +  3], ref v[i +  7], ref v[i + 11], ref v[i + 15]);

                    GB(ref v[i +  0], ref v[i +  5], ref v[i + 10], ref v[i + 15]);
                    GB(ref v[i +  1], ref v[i +  6], ref v[i + 11], ref v[i + 12]);
                    GB(ref v[i +  2], ref v[i +  7], ref v[i +  8], ref v[i + 13]);
                    GB(ref v[i +  3], ref v[i +  4], ref v[i +  9], ref v[i + 14]);
                }

                for (int i = 0; i < 16; i += 2)
                {
                    // Apply P to the column [i + 0 | i + 1], [i + 16 | i + 17], ..., [i + 112 | i + 113]

                    GB(ref v[i +  0], ref v[i + 32], ref v[i + 64], ref v[i +  96]);
                    GB(ref v[i +  1], ref v[i + 33], ref v[i + 65], ref v[i +  97]);
                    GB(ref v[i + 16], ref v[i + 48], ref v[i + 80], ref v[i + 112]);
                    GB(ref v[i + 17], ref v[i + 49], ref v[i + 81], ref v[i + 113]);

                    GB(ref v[i +  0], ref v[i + 33], ref v[i + 80], ref v[i + 113]);
                    GB(ref v[i +  1], ref v[i + 48], ref v[i + 81], ref v[i +  96]);
                    GB(ref v[i + 16], ref v[i + 49], ref v[i + 64], ref v[i +  97]);
                    GB(ref v[i + 17], ref v[i + 32], ref v[i + 65], ref v[i + 112]);
                }
            }

            internal void Fill(Block Y, Block currentBlock)
            {
                Z.CopyBlock(Y);
                ApplyBlake();
                currentBlock.Xor(Y, Z);
            }

            internal void Fill(Block X, Block Y, Block currentBlock)
            {
                R.Xor(X, Y);
                Z.CopyBlock(R);
                ApplyBlake();
                currentBlock.Xor(R, Z);
            }

            internal void FillBlockWithXor(Block X, Block Y, Block currentBlock)
            {
                R.Xor(X, Y);
                Z.CopyBlock(R);
                ApplyBlake();
                currentBlock.XorWith(R, Z);
            }
        }

        private sealed class Block
        {
            private const int Size = Argon2QwordsInBlock;

            /* 128 * 8 Byte QWords */
            internal readonly ulong[] v;

            internal Block()
            {
                v = new ulong[Size];
            }

            internal void FromBytes(byte[] input)
            {
                if (input.Length < Argon2BlockSize)
                    throw new ArgumentException("input shorter than blocksize");

                Pack.LE_To_UInt64(input, 0, v);
            }

            internal void ToBytes(byte[] output)
            {
                if (output.Length < Argon2BlockSize)
                    throw new ArgumentException("output shorter than blocksize");

                Pack.UInt64_To_LE(v, output, 0);
            }

            internal void CopyBlock(Block other)
            {
                Array.Copy(other.v, 0, v, 0, Size);
            }

            internal void Xor(Block b1, Block b2)
            {
                Nat.Xor64(Size, b1.v, b2.v, v);
            }

            internal void XorWith(Block b1)
            {
                Nat.XorTo64(Size, b1.v, v);
            }

            internal void XorWith(Block b1, Block b2)
            {
                Nat.XorBothTo64(Size, b1.v, b2.v, v);
            }

            internal Block Clear()
            {
                Arrays.Fill(v, 0);
                return this;
            }
        }

        private sealed class Position
        {
            internal readonly int pass;
            internal readonly int slice;
            internal readonly int lane;

            internal Position(int pass, int slice, int lane)
            {
                this.pass = pass;
                this.slice = slice;
                this.lane = lane;
            }
        }
    }
}
