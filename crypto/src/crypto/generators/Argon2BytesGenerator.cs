using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class Argon2BytesGenerator
    {
        private const int ARGON2_BLOCK_SIZE = 1024;
        private const int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

        private const int ARGON2_ADDRESSES_IN_BLOCK = 128;

        private const int ARGON2_PREHASH_DIGEST_LENGTH = 64;
        private const int ARGON2_PREHASH_SEED_LENGTH = 72;

        private const int ARGON2_SYNC_POINTS = 4;

        /* Minimum and maximum number of lanes (degree of parallelism) */
        private const int MIN_PARALLELISM = 1;
        private const int MAX_PARALLELISM = 16777216;

        /* Minimum and maximum digest size in bytes */
        private const int MIN_OUTLEN = 4;

        /* Minimum and maximum number of passes */
        private const int MIN_ITERATIONS = 1;

        private const long M32L = 0xFFFFFFFFL;

        private readonly byte[] ZERO_BYTES = new byte[4];

        private Argon2Parameters parameters;
        private Block[] memory;
        private int segmentLength;
        private int laneLength;

        public Argon2BytesGenerator()
        {
        }

        /**
         * Initialise the Argon2BytesGenerator from the parameters.
         *
         * @param parameters Argon2 configuration.
         */
        public void Init(Argon2Parameters parameters)
        {
            this.parameters = parameters;

            if (parameters.GetLanes() < MIN_PARALLELISM)
            {
                throw new InvalidOperationException($"lanes must be greater than " + MIN_PARALLELISM);
            }
            else if (parameters.GetLanes() > MAX_PARALLELISM)
            {
                throw new InvalidOperationException("lanes must be less than " + MAX_PARALLELISM);
            }
            else if (parameters.GetMemory() < 2 * parameters.GetLanes())
            {
                throw new InvalidOperationException("memory is less than: " + (2 * parameters.GetLanes()) + " expected " + (2 * parameters.GetLanes()));
            }
            else if (parameters.GetIterations() < MIN_ITERATIONS)
            {
                throw new InvalidOperationException("iterations is less than: " + MIN_ITERATIONS);
            }

            DoInit(parameters);
        }

        public int GenerateBytes(string password, byte[] output)
        {
            return GenerateBytes(password.ToCharArray(), output);
        }

        public int GenerateBytes(string password, byte[] output, int outOff, int outLen)
        {
            return GenerateBytes(password.ToCharArray(), output, outOff, outLen);
        }

        public int GenerateBytes(char[] password, byte[] output)
        {
            return GenerateBytes(parameters.GetCharToByteConverter().Convert(password), output);
        }

        public int GenerateBytes(char[] password, byte[] output, int outOff, int outLen)
        {
            return GenerateBytes(parameters.GetCharToByteConverter().Convert(password), output, outOff, outLen);
        }

        public int GenerateBytes(byte[] password, byte[] output)
        {
            return GenerateBytes(password, output, 0, output.Length);
        }

        public int GenerateBytes(byte[] password, byte[] output, int outOff, int outLen)
        {
            if (outLen < MIN_OUTLEN)
            {
                throw new InvalidOperationException("output length less than " + MIN_OUTLEN);
            }

            byte[] tmpBlockBytes = new byte[ARGON2_BLOCK_SIZE];

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

        private void DoInit(Argon2Parameters parameters)
        {
            /* 2. Align memory size */
            /* Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
            int memoryBlocks = parameters.GetMemory();

            if (memoryBlocks < 2 * ARGON2_SYNC_POINTS * parameters.GetLanes())
            {
                memoryBlocks = 2 * ARGON2_SYNC_POINTS * parameters.GetLanes();
            }

            this.segmentLength = memoryBlocks / (parameters.GetLanes() * ARGON2_SYNC_POINTS);
            this.laneLength = segmentLength * ARGON2_SYNC_POINTS;

            /* Ensure that all segments have equal length */
            memoryBlocks = segmentLength * (parameters.GetLanes() * ARGON2_SYNC_POINTS);

            InitMemory(memoryBlocks);
        }

        private void InitMemory(int memoryBlocks)
        {
            this.memory = new Block[memoryBlocks];

            for (int i = 0; i < memory.Length; i++)
            {
                memory[i] = new Block();
            }
        }

        private void FillMemoryBlocks()
        {
            FillBlock filler = new FillBlock();
            Position position = new Position();
            for (int pass = 0; pass < parameters.GetIterations(); ++pass)
            {
                position.pass = pass;

                for (int slice = 0; slice < ARGON2_SYNC_POINTS; ++slice)
                {
                    position.slice = slice;

                    for (int lane = 0; lane < parameters.GetLanes(); ++lane)
                    {
                        position.lane = lane;

                        FillSegment(filler, position);
                    }
                }
            }
        }

        private void FillSegment(FillBlock filler, Position position)
        {
            Block addressBlock = null, inputBlock = null;

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
                long pseudoRandom = GetPseudoRandom(
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
            return (parameters.GetArgonType() == Argon2Parameters.ARGON2_i) ||
                (parameters.GetArgonType() == Argon2Parameters.ARGON2_id
                    && (position.pass == 0)
                    && (position.slice < ARGON2_SYNC_POINTS / 2)
                );
        }

        private void InitAddressBlocks(FillBlock filler, Position position, Block inputBlock, Block addressBlock)
        {
            inputBlock.v[0] = (long)position.pass;
            inputBlock.v[1] = (long)position.lane;
            inputBlock.v[2] = (long)position.slice;
            inputBlock.v[3] = (long)memory.Length;
            inputBlock.v[4] = (long)parameters.GetIterations();
            inputBlock.v[5] = (long)parameters.GetArgonType();

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Don't forget to generate the first block of addresses: */
                NextAddresses(filler, inputBlock, addressBlock);
            }
        }

        private bool IsWithXor(Position position)
        {
            return !(position.pass == 0 || parameters.GetVersion() == Argon2Parameters.ARGON2_VERSION_10);
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
        private long GetPseudoRandom(
            FillBlock filler,
            int index,
            Block addressBlock,
            Block inputBlock,
            int prevOffset,
            bool dataIndependentAddressing)
        {
            if (dataIndependentAddressing)
            {
                int addressIndex = index % ARGON2_ADDRESSES_IN_BLOCK;
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

        private int GetRefLane(Position position, long pseudoRandom)
        {
            // Double-casting to/from ulong required because unsigned right shift operator
            // >>> is supported only in C# 11 (.NET 7 or greater)
            int refLane = (int)(((ulong)pseudoRandom >> 32) % (ulong)parameters.GetLanes());

            if ((position.pass == 0) && (position.slice == 0))
            {
                /* Can not reference other lanes yet */
                refLane = position.lane;
            }
            return refLane;
        }

        private int GetRefColumn(Position position, int index, long pseudoRandom, bool sameLane)
        {
            long referenceAreaSize;
            long startPosition;

            if (position.pass == 0)
            {
                startPosition = 0;

                if (sameLane)
                {
                    /* The same lane => add current segment */
                    referenceAreaSize = position.slice * segmentLength + index - 1;
                }
                else
                {
                    /* pass == 0 && !sameLane => position.slice > 0*/
                    referenceAreaSize = position.slice * segmentLength + ((index == 0) ? (-1) : 0);
                }
            }
            else
            {
                startPosition = ((position.slice + 1) * segmentLength) % laneLength;

                if (sameLane)
                {
                    referenceAreaSize = laneLength - segmentLength + index - 1;
                }
                else
                {
                    referenceAreaSize = laneLength - segmentLength + ((index == 0) ? (-1) : 0);
                }
            }

            long relativePosition = pseudoRandom & 0xFFFFFFFFL;

            // Double-casting to/from ulong required because unsigned right shift operator
            // >>> is supported only in C# 11 (.NET 7 or greater)
            relativePosition = (long)((ulong)(relativePosition * relativePosition) >> 32);
            relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >> 32);

            return (int)(startPosition + relativePosition) % laneLength;
        }

        private void Digest(byte[] tmpBlockBytes, byte[] output, int outOff, int outLen)
        {
            Block finalBlock = memory[laneLength - 1];

            /* XOR the last blocks */
            for (int i = 1; i < parameters.GetLanes(); i++)
            {
                int lastBlockInLane = i * laneLength + (laneLength - 1);
                finalBlock.XorWith(memory[lastBlockInLane]);
            }

            finalBlock.ToBytes(tmpBlockBytes);

            Hash(tmpBlockBytes, output, outOff, outLen);
        }

        /**
         * H' - hash - variable length hash function
         */
        private static void Hash(byte[] input, byte[] output, int outOff, int outLen)
        {
            byte[] outLenBytes = new byte[4];
            Pack.UInt32_To_LE((uint)outLen, outLenBytes, 0);

            int blake2bLength = 64;

            if (outLen <= blake2bLength)
            {
                IDigest blake = new Blake2bDigest(outLen * 8);

                blake.BlockUpdate(outLenBytes, 0, outLenBytes.Length);
                blake.BlockUpdate(input, 0, input.Length);
                blake.DoFinal(output, outOff);
            }
            else
            {
                IDigest digest = new Blake2bDigest(blake2bLength * 8);
                byte[] outBuffer = new byte[blake2bLength];

                /* V1 */
                digest.BlockUpdate(outLenBytes, 0, outLenBytes.Length);
                digest.BlockUpdate(input, 0, input.Length);
                digest.DoFinal(outBuffer, 0);

                int halfLen = blake2bLength / 2, outPos = outOff;
                Array.Copy(outBuffer, 0, output, outPos, halfLen);
                outPos += halfLen;

                int r = ((outLen + 31) / 32) - 2;

                for (int i = 2; i <= r; i++, outPos += halfLen)
                {
                    /* V2 to Vr */
                    digest.BlockUpdate(outBuffer, 0, outBuffer.Length);
                    digest.DoFinal(outBuffer, 0);

                    Array.Copy(outBuffer, 0, output, outPos, halfLen);
                }

                int lastLength = outLen - 32 * r;

                /* Vr+1 */
                digest = new Blake2bDigest(lastLength * 8);

                digest.BlockUpdate(outBuffer, 0, outBuffer.Length);
                digest.DoFinal(output, outPos);
            }
        }

        private static void RoundFunction(Block block,
                                          int v0, int v1, int v2, int v3,
                                          int v4, int v5, int v6, int v7,
                                          int v8, int v9, int v10, int v11,
                                          int v12, int v13, int v14, int v15)
        {
            long[] v = block.v;

            F(v, v0, v4, v8, v12);
            F(v, v1, v5, v9, v13);
            F(v, v2, v6, v10, v14);
            F(v, v3, v7, v11, v15);

            F(v, v0, v5, v10, v15);
            F(v, v1, v6, v11, v12);
            F(v, v2, v7, v8, v13);
            F(v, v3, v4, v9, v14);
        }

        private static void F(long[] v, int a, int b, int c, int d)
        {
            QuarterRound(v, a, b, d, 32);
            QuarterRound(v, c, d, b, 24);
            QuarterRound(v, a, b, d, 16);
            QuarterRound(v, c, d, b, 63);
        }

        private static void QuarterRound(long[] v, int x, int y, int z, int s)
        {
            //        fBlaMka(v, x, y);
            //        rotr64(v, z, x, s);

            long a = v[x], b = v[y], c = v[z];

            a += b + 2 * (a & M32L) * (b & M32L);
            c = Longs.RotateRight(c ^ a, s);

            v[x] = a;
            v[z] = c;
        }

        /*designed by the Lyra PHC team */
        /* a <- a + b + 2*aL*bL
         * + == addition modulo 2^64
         * aL = least 32 bit */
        //    private static void fBlaMka(long[] v, int x, int y)
        //    {
        //        final long a = v[x], b = v[y];
        //        final long ab = (a & M32L) * (b & M32L);
        //
        //        v[x] = a + b + 2 * ab;
        //    }
        //
        //    private static void rotr64(long[] v, int x, int y, int s)
        //    {
        //        v[x] = Longs.rotateRight(v[x] ^ v[y], s);
        //    }

        private void Initialize(byte[] tmpBlockBytes, byte[] password, int outputLength)
        {
            /*
             * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
             * -> 64 byte (ARGON2_PREHASH_DIGEST_LENGTH)
             */

            Blake2bDigest blake = new Blake2bDigest(ARGON2_PREHASH_DIGEST_LENGTH * 8);

            int[] values = {
                parameters.GetLanes(),
                outputLength,
                parameters.GetMemory(),
                parameters.GetIterations(),
                parameters.GetVersion(),
                parameters.GetArgonType()
            };

            Helpers.IntArrayToLittleEndian(values, tmpBlockBytes, 0);
            blake.BlockUpdate(tmpBlockBytes, 0, values.Length * 4);

            AddByteString(tmpBlockBytes, blake, password);
            AddByteString(tmpBlockBytes, blake, parameters.GetSalt());
            AddByteString(tmpBlockBytes, blake, parameters.GetSecret());
            AddByteString(tmpBlockBytes, blake, parameters.GetAdditional());

            byte[] initialHashWithZeros = new byte[ARGON2_PREHASH_SEED_LENGTH];
            blake.DoFinal(initialHashWithZeros, 0);

            FillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
        }

        private void AddByteString(byte[] tmpBlockBytes, IDigest digest, byte[] octets)
        {
            if (null == octets)
            {
                digest.BlockUpdate(ZERO_BYTES, 0, 4);
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
            byte[] initialHashWithOnes = new byte[ARGON2_PREHASH_SEED_LENGTH];
            Array.Copy(initialHashWithZeros, 0, initialHashWithOnes, 0, ARGON2_PREHASH_DIGEST_LENGTH);
            //        Pack.intToLittleEndian(1, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH);
            initialHashWithOnes[ARGON2_PREHASH_DIGEST_LENGTH] = 1;

            for (int i = 0; i < parameters.GetLanes(); i++)
            {
                Pack.UInt32_To_LE((uint)i, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
                Pack.UInt32_To_LE((uint)i, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

                Hash(initialHashWithZeros, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
                memory[i * laneLength + 0].FromBytes(tmpBlockBytes);

                Hash(initialHashWithOnes, tmpBlockBytes, 0, ARGON2_BLOCK_SIZE);
                memory[i * laneLength + 1].FromBytes(tmpBlockBytes);
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
                /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
                (16,17,..31)... finally (112,113,...127) */
                for (int i = 0; i < 8; i++)
                {

                    int i16 = 16 * i;
                    RoundFunction(Z,
                        i16, i16 + 1, i16 + 2,
                        i16 + 3, i16 + 4, i16 + 5,
                        i16 + 6, i16 + 7, i16 + 8,
                        i16 + 9, i16 + 10, i16 + 11,
                        i16 + 12, i16 + 13, i16 + 14,
                        i16 + 15
                    );
                }

                /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
                (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
                for (int i = 0; i < 8; i++)
                {

                    int i2 = 2 * i;
                    RoundFunction(Z,
                        i2, i2 + 1, i2 + 16,
                        i2 + 17, i2 + 32, i2 + 33,
                        i2 + 48, i2 + 49, i2 + 64,
                        i2 + 65, i2 + 80, i2 + 81,
                        i2 + 96, i2 + 97, i2 + 112,
                        i2 + 113
                    );
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
            private const int SIZE = ARGON2_QWORDS_IN_BLOCK;

            /* 128 * 8 Byte QWords */
            internal readonly long[] v;

            internal Block()
            {
                v = new long[SIZE];
            }

            internal void FromBytes(byte[] input)
            {
                if (input.Length < ARGON2_BLOCK_SIZE)
                {
                    throw new ArgumentException("input shorter than blocksize");
                }

                Helpers.LittleEndianToLongArray(input, 0, v);
            }

           internal void ToBytes(byte[] output)
            {
                if (output.Length < ARGON2_BLOCK_SIZE)
                {
                    throw new ArgumentException("output shorter than blocksize");
                }

                Helpers.LongArrayToLittleEndian(v, output, 0);
            }

            internal void CopyBlock(Block other)
            {
                Array.Copy(other.v, 0, v, 0, SIZE);
            }

            internal void Xor(Block b1, Block b2)
            {
                long[] v0 = v;
                long[] v1 = b1.v;
                long[] v2 = b2.v;

                for (int i = 0; i < SIZE; i++)
                {
                    v0[i] = v1[i] ^ v2[i];
                }
            }

            internal void XorWith(Block b1)
            {
                long[] v0 = v;
                long[] v1 = b1.v;

                for (int i = 0; i < SIZE; i++)
                {
                    v0[i] ^= v1[i];
                }
            }

            internal void XorWith(Block b1, Block b2)
            {
                long[] v0 = v;
                long[] v1 = b1.v;
                long[] v2 = b2.v;
                for (int i = 0; i < SIZE; i++)
                {
                    v0[i] ^= v1[i] ^ v2[i];
                }
            }

            internal Block Clear()
            {
                Arrays.Fill(v, 0);
                return this;
            }
        }

        private sealed class Position
        {
            internal int pass;
            internal int lane;
            internal int slice;

            internal Position()
            {
            }
        }

        private static class Helpers
        {
            internal static void LittleEndianToLongArray(byte[] bs, int off, long[] ns)
            {
                for (int i = 0; i < ns.Length; ++i)
                {
                    ns[i] = (long)Pack.LE_To_UInt64(bs, off);
                    off += 8;
                }
            }

            internal static void LongArrayToLittleEndian(long[] ns, byte[] bs, int off)
            {
                for (int i = 0; i < ns.Length; ++i)
                {
                    Pack.UInt64_To_LE((ulong)ns[i], bs, off);
                    off += 8;
                }
            }

            internal static void IntArrayToLittleEndian(int[] ns, byte[] bs, int off)
            {
                for (int i = 0; i < ns.Length; ++i)
                {
                    Pack.UInt32_To_LE((uint)ns[i], bs, off);
                    off += 4;
                }
            }

        }
    }
}
