using System;

using Org.BouncyCastle.Crypto.Generators;
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
        private readonly Argon2BytesGenerator.IBlockPool blockPool;

        /// <summary>Fluent builder for <see cref="Argon2Parameters"/>.</summary>
        public sealed class Builder
        {
            private static readonly int DefaultIterations = 3;
            private static readonly int DefaultMemoryCost = 12;
            private static readonly int DefaultParallelism = 1;
            private static readonly int DefaultType = Argon2i;
            private static readonly int DefaultVersion = Version13;

            private readonly int m_type;
            private readonly int m_maxIterations;
            private readonly int m_maxMemory;
            private readonly int m_maxParallelism;
            private readonly bool m_allowLegacyMemory;

            private byte[] salt = Array.Empty<byte>();
            private byte[] secret = Array.Empty<byte>();
            private byte[] additional = Array.Empty<byte>();
            private int iterations = DefaultIterations;
            private int memory = 1 << DefaultMemoryCost;
            private int parallelism = DefaultParallelism;
            private int version = DefaultVersion;
            private ICharToByteConverter converter = PasswordConverter.Utf8;
            private Argon2BytesGenerator.IBlockPool blockPool;

            /// <summary>Create a builder defaulting to <see cref="Argon2i"/>, for trusted cost parameters.</summary>
            /// <exception cref="InvalidOperationException">
            /// If the <see cref="Properties.Argon2MaxMemoryExp"/> property is set too low.
            /// </exception>
            public Builder()
                : this(DefaultType)
            {
            }

            /// <summary>Create a builder for the given Argon2 variant, for trusted cost parameters.</summary>
            /// <param name="type">
            /// One of <see cref="Argon2d"/>, <see cref="Argon2i"/>, or <see cref="Argon2id"/>.
            /// </param>
            /// <exception cref="InvalidOperationException">
            /// If the <see cref="Properties.Argon2MaxMemoryExp"/> property is set too low.
            /// </exception>
            public Builder(int type)
                : this(type, trusted: true)
            {
            }

            /// <summary>Create a builder for the given Argon2 variant.</summary>
            /// <param name="type">
            /// One of <see cref="Argon2d"/>, <see cref="Argon2i"/>, or <see cref="Argon2id"/>.
            /// </param>
            /// <param name="trusted">
            /// Whether the cost parameters come from a trusted source. If <c>false</c>, the iterations and the
            /// parallelism are also limited by the <see cref="Properties.Argon2MaxPasses"/> and
            /// <see cref="Properties.Argon2MaxParallelism"/> properties, and the
            /// <see cref="Properties.Argon2AllowLegacyMemory"/> property is ignored. The memory is always limited by
            /// the <see cref="Properties.Argon2MaxMemoryExp"/> property.
            /// </param>
            /// <exception cref="InvalidOperationException">If an applicable limit property is set too low.</exception>
            public Builder(int type, bool trusted)
            {
                m_type = type;
                // RFC 9106 allows up to 2^32 - 1 passes, but they are held as a signed 32-bit count, so int.MaxValue
                // is the ceiling regardless.
                m_maxIterations = GetLimit(!trusted, Properties.Argon2MaxPasses, 10, 1, int.MaxValue);
                // Memory is held as a signed 32-bit count of KiB, so 30 is the ceiling regardless. The property
                // applies even to trusted cost parameters, for compatibility with earlier versions.
                m_maxMemory = GetLimit(true, Properties.Argon2MaxMemoryExp, 24, 3, 30);
                m_maxParallelism = GetLimit(!trusted, Properties.Argon2MaxParallelism, 16, 1, (1 << 24) - 1);
                m_allowLegacyMemory = trusted && Properties.GetBoolean(Properties.Argon2AllowLegacyMemory, false);
            }

            /// <summary>Set the parallelism (number of lanes).</summary>
            /// <param name="parallelism">
            /// The degree of parallelism, must be at least 1, and less than <c>1 &lt;&lt; 24</c>. For untrusted
            /// cost parameters, it must also be at most the limit set by <see cref="Properties.Argon2MaxParallelism"/>.
            /// </param>
            /// <returns>This builder.</returns>
            public Builder WithParallelism(int parallelism)
            {
                if (parallelism < 1 || parallelism > m_maxParallelism)
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
            /// <param name="iterations">
            /// Number of iterations, must be at least 1. For untrusted cost parameters, it must also be at most the
            /// limit set by <see cref="Properties.Argon2MaxPasses"/>.
            /// </param>
            /// <returns>This builder.</returns>
            public Builder WithIterations(int iterations)
            {
                if (iterations < 1 || iterations > m_maxIterations)
                    throw new ArgumentOutOfRangeException(nameof(iterations));

                this.iterations = iterations;
                return this;
            }

            /// <summary>Set the memory cost expressed directly in KiB.</summary>
            /// <param name="memory">
            /// Memory in KiB; must be in <c>[8, 1 &lt;&lt; MaxMemoryExp]</c> (or from 1, if legacy memory sizes are
            /// allowed; see <see cref="Properties.Argon2AllowLegacyMemory"/>).
            /// </param>
            /// <returns>This builder.</returns>
            /// <exception cref="ArgumentOutOfRangeException">If the value is out of range.</exception>
            public Builder WithMemoryAsKB(int memory)
            {
                int minMemory = m_allowLegacyMemory ? 0 : 3;
                if (memory < (1 << minMemory) || memory > (1 << m_maxMemory))
                    throw new ArgumentOutOfRangeException(nameof(memory));

                this.memory = memory;
                return this;
            }

            /// <summary>
            /// Set the memory cost as a power of two: the resulting memory in KiB is <c>1 &lt;&lt; memory.</c>.
            /// </summary>
            /// <param name="memory">
            /// Exponent; must be in <c>[3, MaxMemoryExp]</c> (or from 0, if legacy memory sizes are allowed; see
            /// <see cref="Properties.Argon2AllowLegacyMemory"/>).
            /// </param>
            /// <returns>This builder.</returns>
            /// <exception cref="ArgumentOutOfRangeException">If the exponent is out of range.</exception>
            public Builder WithMemoryPowOfTwo(int memory)
            {
                // Actual range is supposed to be 31 - int's are signed here so cutoff is at 2**30
                int minMemory = m_allowLegacyMemory ? 0 : 3;
                if (memory < minMemory || memory > m_maxMemory)
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

            /// <summary>
            /// Provide a custom <see cref="Argon2BytesGenerator.IBlockPool"/> for the generator to take its working
            /// blocks from.
            /// </summary>
            /// <remarks>
            /// Useful in high-throughput scenarios where the cost of allocating fresh blocks for each call dominates,
            /// e.g. to share blocks among generators. If <c>null</c> (the default), each generator allocates its own
            /// blocks and keeps them between calls.
            /// </remarks>
            /// <param name="blockPool">The block pool to use; may be <c>null</c>.</param>
            /// <returns>This builder.</returns>
            public Builder WithBlockPool(Argon2BytesGenerator.IBlockPool blockPool)
            {
                this.blockPool = blockPool;
                return this;
            }

            /// <summary>Construct immutable <see cref="Argon2Parameters"/> from the current builder state.</summary>
            /// <returns>The configured parameters.</returns>
            /// <exception cref="InvalidOperationException">
            /// If the memory is less than the minimum of <c>8 * parallelism</c> KiB that RFC 9106 sec. 3.1 requires,
            /// unless the cost parameters are trusted and <see cref="Properties.Argon2AllowLegacyMemory"/> is set.
            /// </exception>
            public Argon2Parameters Build()
            {
                // Checked here, rather than in the setters, since memory and parallelism may be set in either order
                if (memory < 8 * parallelism && !m_allowLegacyMemory)
                    throw new InvalidOperationException("memory must be at least 8 * parallelism KiB");

                return new Argon2Parameters(m_type, salt, secret, additional, iterations, memory, parallelism, version,
                    converter, blockPool);
            }

            /// <summary>Zeroise sensitive state (salt, secret, additional) held by this builder.</summary>
            public void Clear()
            {
                Arrays.ZeroMemory(salt);
                Arrays.ZeroMemory(secret);
                Arrays.ZeroMemory(additional);
            }

            // Without useProperty, the limit is just maxValue (the most Argon2 allows). A property limit below
            // minValue would reject every value, so it is reported as a configuration error; one above maxValue is
            // no limit, so it is clamped.
            private static int GetLimit(bool useProperty, string propertyName, int defaultValue, int minValue,
                int maxValue)
            {
                if (!useProperty)
                    return maxValue;

                int limit = Properties.GetInt32(propertyName, defaultValue);
                if (limit < minValue)
                    throw new InvalidOperationException($"{propertyName} out of range");

                return System.Math.Min(limit, maxValue);
            }
        }

        private Argon2Parameters(int type, byte[] salt, byte[] secret, byte[] additional, int iterations, int memory,
            int parallelism, int version, ICharToByteConverter converter, Argon2BytesGenerator.IBlockPool blockPool)
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
            this.blockPool = blockPool;
        }

        /// <returns>
        /// The user-supplied <see cref="Argon2BytesGenerator.IBlockPool"/>, or <c>null</c> if the generator should
        /// allocate its own blocks.
        /// </returns>
        public Argon2BytesGenerator.IBlockPool BlockPool => blockPool;

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
