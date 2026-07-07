using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class Argon2Parameters
    {
        /// <summary>Argon2d - data-dependent memory access.</summary>
        public static readonly int Argon2d = 0x00;
        /// <summary>Argon2i - data-independent memory access.</summary>
        public static readonly int Argon2i = 0x01;
        /// <summary>Argon2id - hybrid of <see cref="Argon2i"/> and <see cref="Argon2d"/>.</summary>
        public static readonly int Argon2id = 0x02;

        /// <summary>Argon2 v1.0 (legacy).</summary>
        public static readonly int Version10 = 0x10;
        /// <summary>Argon2 v1.3 - the version standardised by RFC 9106.</summary>
        public static readonly int Version13 = 0x13;

        private readonly int type;
        private readonly byte[] salt;
        private readonly byte[] secret;
        private readonly byte[] additional;
        private readonly int iterations;
        private readonly int memory;
        private readonly int parallelism;
        private readonly int version;
        private readonly ICharToByteConverter converter;

        /// <summary>Fluent builder for <see cref="Argon2Parameters"/>.</summary>
        public sealed class Builder
        {
            private static readonly int DefaultIterations = 3;
            private static readonly int DefaultMemoryCost = 12;
            private static readonly int DefaultParallelism = 1;
            private static readonly int DefaultType = Argon2i;
            private static readonly int DefaultVersion = Version13;

            private readonly int m_type;
            private readonly int m_maxMemory;

            private byte[] salt = Array.Empty<byte>();
            private byte[] secret = Array.Empty<byte>();
            private byte[] additional = Array.Empty<byte>();
            private int iterations = DefaultIterations;
            private int memory = 1 << DefaultMemoryCost;
            private int parallelism = DefaultParallelism;
            private int version = DefaultVersion;
            private ICharToByteConverter converter = PasswordConverter.Utf8;

            /// <summary>Create a builder defaulting to <see cref="Argon2i"/>.</summary>
            public Builder()
                : this(DefaultType)
            {
            }

            /// <summary>Create a builder for the given Argon2 variant.</summary>
            /// <param name="type">
            /// One of <see cref="Argon2d"/>, <see cref="Argon2i"/>, or <see cref="Argon2id"/>.
            /// </param>
            public Builder(int type)
            {
                m_type = type;
                m_maxMemory = Properties.GetInt32(Properties.Argon2MaxMemoryExp, 24);
                if (m_maxMemory < 3 || m_maxMemory > 30)
                    throw new InvalidOperationException($"{Properties.Argon2MaxMemoryExp} out of range");
            }

            /// <summary>Set the parallelism (number of lanes).</summary>
            /// <param name="parallelism">
            /// The degree of parallelism, must be at least 1, and less than <c>1 << 24</c>.
            /// </param>
            /// <returns>This builder.</returns>
            public Builder WithParallelism(int parallelism)
            {
                if (parallelism < 1 || parallelism >= (1 << 24))
                    throw new ArgumentOutOfRangeException(nameof(parallelism));

                this.parallelism = parallelism;
                return this;
            }

            /// <summary>Set the salt.</summary>
            /// <remarks>The supplied array is defensively cloned.</remarks>
            /// <param name="salt">Salt bytes; may be <c>null</c>.</param>
            /// <returns>This builder.</returns>
            public Builder WithSalt(byte[] salt)
            {
                this.salt = Arrays.Clone(salt);
                return this;
            }

            /// <summary>Set the optional secret (key) value.</summary>
            /// <remarks>The supplied array is defensively cloned.</remarks>
            /// <param name="secret">Secret bytes; may be <c>null</c>.</param>
            /// <returns>This builder.</returns>
            public Builder WithSecret(byte[] secret)
            {
                this.secret = Arrays.Clone(secret);
                return this;
            }

            /// <summary>Set the optional additional/associated data.</summary>
            /// <remarks>The supplied array is defensively cloned.</remarks>
            /// <param name="additional">Additional data bytes; may be <c>null</c>.</param>
            /// <returns>This builder.</returns>
            public Builder WithAdditional(byte[] additional)
            {
                this.additional = Arrays.Clone(additional);
                return this;
            }

            /// <summary>Set the number of passes (time cost).</summary>
            /// <param name="iterations">Number of iterations, must be at least 1.</param>
            /// <returns>This builder.</returns>
            public Builder WithIterations(int iterations)
            {
                if (iterations < 1)
                    throw new ArgumentOutOfRangeException(nameof(iterations));

                this.iterations = iterations;
                return this;
            }

            /// <summary>Set the memory cost expressed directly in KiB.</summary>
            /// <param name="memory">Memory in KiB; must be in <c>[1, 1 &lt;&lt; MaxMemoryExp]</c>.</param>
            /// <returns>This builder.</returns>
            /// <exception cref="ArgumentOutOfRangeException">If the value is out of range.</exception>
            public Builder WithMemoryAsKB(int memory)
            {
                if (memory < 1 || memory > (1 << m_maxMemory))
                    throw new ArgumentOutOfRangeException(nameof(memory));

                this.memory = memory;
                return this;
            }

            /// <summary>
            /// Set the memory cost as a power of two: the resulting memory in KiB is <c>1 &lt;&lt; memory.</c>.
            /// </summary>
            /// <param name="memory">Exponent; must be in <c>[0, MaxMemoryExp]</c>.</param>
            /// <returns>This builder.</returns>
            /// <exception cref="ArgumentOutOfRangeException">If the exponent is out of range.</exception>
            public Builder WithMemoryPowOfTwo(int memory)
            {
                // Actual range is supposed to be 31 - int's are signed here so cutoff is at 2**30
                if (memory < 0 || memory > m_maxMemory)
                    throw new ArgumentOutOfRangeException(nameof(memory));

                this.memory = 1 << memory;
                return this;
            }

            /// <summary>Set the Argon2 version.</summary>
            /// <param name="version">One of <see cref="Version10"/> or <see cref="Version13"/>.</param>
            /// <returns>This builder.</returns>
            public Builder WithVersion(int version)
            {
                this.version = version;
                return this;
            }

            /// <summary>Override the converter used to turn <c>char[]</c> passwords into bytes.</summary>
            /// <remarks>Default is <see cref="PasswordConverter.Utf8"/>.</remarks>
            /// <param name="converter">The character-to-byte converter to use.</param>
            /// <returns>This builder.</returns>
            public Builder WithCharToByteConverter(ICharToByteConverter converter)
            {
                this.converter = converter;
                return this;
            }

            /// <summary>Construct immutable <see cref="Argon2Parameters"/> from the current builder state.</summary>
            /// <returns>The configured parameters.</returns>
            public Argon2Parameters Build()
            {
                return new Argon2Parameters(m_type, salt, secret, additional, iterations, memory, parallelism, version,
                    converter);
            }

            /// <summary>Zeroise sensitive state (salt, secret, additional) held by this builder.</summary>
            public void Clear()
            {
                Arrays.ZeroMemory(salt);
                Arrays.ZeroMemory(secret);
                Arrays.ZeroMemory(additional);
            }
        }

        private Argon2Parameters(int type, byte[] salt, byte[] secret, byte[] additional, int iterations, int memory,
            int parallelism, int version, ICharToByteConverter converter)
        {
            this.type = type;
            this.salt = salt;
            this.secret = secret;
            this.additional = additional;
            this.iterations = iterations;
            this.memory = memory;
            this.parallelism = parallelism;
            this.version = version;
            this.converter = converter;
        }

        /// <returns>The character-to-byte converter used to encode <c>char[]</c> passwords.</returns>
        public ICharToByteConverter CharToByteConverter => converter;

        /// <returns>A defensive copy of the salt, or <c>null</c> if none was set.</returns>
        public byte[] GetSalt() => Arrays.Clone(salt);

        /// <returns>A defensive copy of the secret value, or <c>null</c> if none was set.</returns>
        public byte[] GetSecret() => Arrays.Clone(secret);

        /// <returns>A defensive copy of the additional data, or <c>null</c> if none was set.</returns>
        public byte[] GetAdditional() => Arrays.Clone(additional);

        /// <returns>The number of passes (time cost).</returns>
        public int Iterations => iterations;

        /// <returns>The parallelism (lane count).</returns>
        public int Parallelism => parallelism;

        /// <returns>The memory cost in KiB.</returns>
        public int Memory => memory;

        /// <returns>
        /// The Argon2 variant constant (<see cref="Argon2d"/>, <see cref="Argon2i"/>, or <see cref="Argon2id"/>).
        /// </returns>
        public int Type => type;

        /// <returns>The Argon2 version constant (<see cref="Version10"/> or <see cref="Version13"/>).</returns>
        public int Version => version;

        /// <summary>Zeroise sensitive state (salt, secret, additional) held by these parameters.</summary>
        public void Clear()
        {
            Arrays.ZeroMemory(salt);
            Arrays.ZeroMemory(secret);
            Arrays.ZeroMemory(additional);
        }

        internal byte[] Additional => additional;

        internal byte[] Salt => salt;

        internal byte[] Secret => secret;
    }
}
