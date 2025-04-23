using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Crypto
{
    public abstract class BufferedCipherBase
        : IBufferedCipher
    {
        // TODO[api] Hide/remove
        protected static readonly byte[] EmptyBuffer = new byte[0];

        public abstract string AlgorithmName { get; }

        public abstract void Init(bool forEncryption, ICipherParameters parameters);

        public abstract int GetBlockSize();

        public abstract int GetOutputSize(int inputLen);
        public abstract int GetUpdateOutputSize(int inputLen);

        public abstract byte[] ProcessByte(byte input);

        public virtual int ProcessByte(
            byte input,
            byte[] output,
            int outOff)
        {
            byte[] outBytes = ProcessByte(input);
            if (outBytes == null)
                return 0;
            if (outOff + outBytes.Length > output.Length)
                throw new DataLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract int ProcessByte(byte input, Span<byte> output);
#endif

        public virtual byte[] ProcessBytes(
            byte[] input)
        {
            return ProcessBytes(input, 0, input.Length);
        }

        public abstract byte[] ProcessBytes(byte[] input, int inOff, int length);

        public virtual int ProcessBytes(
            byte[] input,
            byte[] output,
            int outOff)
        {
            return ProcessBytes(input, 0, input.Length, output, outOff);
        }

        public virtual int ProcessBytes(
            byte[] input,
            int inOff,
            int length,
            byte[] output,
            int outOff)
        {
            byte[] outBytes = ProcessBytes(input, inOff, length);
            if (outBytes == null)
                return 0;
            if (outOff + outBytes.Length > output.Length)
                throw new DataLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        public abstract byte[] DoFinal();

        public virtual byte[] DoFinal(
            byte[] input)
        {
            return DoFinal(input, 0, input.Length);
        }

        public abstract byte[] DoFinal(
            byte[] input,
            int inOff,
            int length);

        public virtual int DoFinal(
            byte[] output,
            int outOff)
        {
            byte[] outBytes = DoFinal();
            if (outOff + outBytes.Length > output.Length)
                throw new DataLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }

        public virtual int DoFinal(
            byte[] input,
            byte[] output,
            int outOff)
        {
            return DoFinal(input, 0, input.Length, output, outOff);
        }

        public virtual int DoFinal(
            byte[] input,
            int inOff,
            int length,
            byte[] output,
            int outOff)
        {
            int len = ProcessBytes(input, inOff, length, output, outOff);
            len += DoFinal(output, outOff + len);
            return len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract int DoFinal(Span<byte> output);

        public virtual int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int len = ProcessBytes(input, output);
            len += DoFinal(output[len..]);
            return len;
        }
#endif

        public abstract void Reset();

        internal static int GetFullBlocksSize(int totalSize, int blockSize)
        {
            Debug.Assert(blockSize > 0);

            if (totalSize < 0)
                return 0;

            int blockSizeMask = blockSize - 1;
            if ((blockSize & blockSizeMask) == 0)
                return totalSize & ~blockSizeMask;

            return totalSize - totalSize % blockSize;
        }

        internal static bool SegmentsOverlap(int aOff, int aLen, int bOff, int bLen)
        {
            return aLen > 0
                && bLen > 0
                && aOff < bOff + bLen
                && bOff < aOff + aLen;
        }
    }
}
