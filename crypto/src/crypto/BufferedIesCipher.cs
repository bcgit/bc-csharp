using System;
using System.IO;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    public class BufferedIesCipher
        : BufferedCipherBase
    {
        private readonly IesEngine m_engine;
        private bool forEncryption;
        private MemoryStream buffer = new MemoryStream();

        /// <summary>Create a new <see cref="BufferedIesCipher"/>.</summary>
        /// <param name="engine">The underlying engine.</param>
        public BufferedIesCipher(IesEngine engine)
        {
            m_engine = engine ?? throw new ArgumentNullException(nameof(engine));
        }

        /// <inheritdoc/>
        // TODO Create IESEngine.AlgorithmName
        public override string AlgorithmName => "IES";

        /// <inheritdoc/>
        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            // TODO
            throw new NotImplementedException("IES");
        }

        /// <inheritdoc/>
        public override int GetBlockSize() => 0;

        /// <inheritdoc/>
        public override int GetOutputSize(int inputLen)
        {
            // TODO m_engine is not null by construction, need different test once Init implemented
            if (m_engine == null)
                throw new InvalidOperationException("cipher not initialised");

            int baseLen = inputLen + Convert.ToInt32(buffer.Length);
            return forEncryption
                ? baseLen + 20
                : baseLen - 20;
        }

        /// <inheritdoc/>
        public override int GetUpdateOutputSize(int inputLen) => 0;

        /// <inheritdoc/>
        public override byte[] ProcessByte(byte input)
        {
            buffer.WriteByte(input);
            return null;
        }

        /// <inheritdoc/>
        public override int ProcessByte(byte input, byte[] output, int outOff)
        {
            buffer.WriteByte(input);
            return 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int ProcessByte(byte input, Span<byte> output)
        {
            buffer.WriteByte(input);
            return 0;
        }
#endif

        /// <inheritdoc/>
        public override byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            Arrays.ValidateSegment(input, inOff, length);

            buffer.Write(input, inOff, length);
            return null;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            buffer.Write(input);
            return 0;
        }
#endif

        /// <inheritdoc/>
        public override byte[] DoFinal()
        {
            byte[] buf = buffer.ToArray();

            Reset();

            return m_engine.ProcessBlock(buf, 0, buf.Length);
        }

        /// <inheritdoc/>
        public override byte[] DoFinal(byte[] input, int inOff, int length)
        {
            ProcessBytes(input, inOff, length);
            return DoFinal();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int DoFinal(Span<byte> output)
        {
            byte[] buf = buffer.ToArray();

            Reset();

            byte[] block = m_engine.ProcessBlock(buf, 0, buf.Length);
            block.CopyTo(output);
            return block.Length;
        }
#endif

        /// <inheritdoc/>
        public override void Reset() => buffer.SetLength(0);
    }
}
