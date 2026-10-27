using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base class for buffered ciphers, providing default implementations for the convenience overloads.
    /// </summary>
    public abstract class BufferedCipherBase
        : IBufferedCipher
    {
        /// <summary>A shared empty buffer.</summary>
        // TODO[api] Hide/remove
        [Obsolete("Will be removed")]
        protected static readonly byte[] EmptyBuffer = new byte[0];

        /// <inheritdoc/>
        public abstract string AlgorithmName { get; }

        /// <inheritdoc/>
        public abstract void Init(bool forEncryption, ICipherParameters parameters);

        /// <inheritdoc/>
        public abstract int GetBlockSize();

        /// <inheritdoc/>
        public abstract int GetOutputSize(int inputLen);

        /// <inheritdoc/>
        public abstract int GetUpdateOutputSize(int inputLen);

        /// <inheritdoc/>
        public abstract byte[] ProcessByte(byte input);

        /// <inheritdoc/>
        public virtual int ProcessByte(byte input, byte[] output, int outOff)
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
        /// <inheritdoc/>
        public abstract int ProcessByte(byte input, Span<byte> output);
#endif

        /// <inheritdoc/>
        public virtual byte[] ProcessBytes(byte[] input) => ProcessBytes(input, 0, input.Length);

        /// <inheritdoc/>
        public abstract byte[] ProcessBytes(byte[] input, int inOff, int length);

        /// <inheritdoc/>
        public virtual int ProcessBytes(byte[] input, byte[] output, int outOff) =>
            ProcessBytes(input, 0, input.Length, output, outOff);

        /// <inheritdoc/>
        public virtual int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
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
        /// <inheritdoc/>
        public abstract int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);
#endif

        /// <inheritdoc/>
        public abstract byte[] DoFinal();

        /// <inheritdoc/>
        public virtual byte[] DoFinal(byte[] input) => DoFinal(input, 0, input.Length);

        /// <inheritdoc/>
        public abstract byte[] DoFinal(byte[] input, int inOff, int length);

        /// <inheritdoc/>
        public virtual int DoFinal(byte[] output, int outOff)
        {
            byte[] outBytes = DoFinal();
            if (outOff + outBytes.Length > output.Length)
                throw new DataLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }

        /// <inheritdoc/>
        public virtual int DoFinal(byte[] input, byte[] output, int outOff) =>
            DoFinal(input, 0, input.Length, output, outOff);

        /// <inheritdoc/>
        public virtual int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            int len = ProcessBytes(input, inOff, length, output, outOff);
            len += DoFinal(output, outOff + len);
            return len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public abstract int DoFinal(Span<byte> output);

        /// <inheritdoc/>
        public virtual int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int len = ProcessBytes(input, output);
            len += DoFinal(output[len..]);
            return len;
        }
#endif

        /// <inheritdoc/>
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
    }
}
