using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class Argon2Parameters
    {
        public static readonly int Argon2d = 0x00;
        public static readonly int Argon2i = 0x01;
        public static readonly int Argon2id = 0x02;

        public static readonly int Version10 = 0x10;
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

        public sealed class Builder
        {
            private static readonly int DefaultIterations = 3;
            private static readonly int DefaultMemoryCost = 12;
            private static readonly int DefaultParallelism = 1;
            private static readonly int DefaultType = Argon2i;
            private static readonly int DefaultVersion = Version13;

            private readonly int type;

            private byte[] salt = Array.Empty<byte>();
            private byte[] secret = Array.Empty<byte>();
            private byte[] additional = Array.Empty<byte>();
            private int iterations = DefaultIterations;
            private int memory = 1 << DefaultMemoryCost;
            private int parallelism = DefaultParallelism;
            private int version = DefaultVersion;
            private ICharToByteConverter converter = PasswordConverter.Utf8;

            public Builder()
                : this(DefaultType)
            {
            }

            public Builder(int type)
            {
                this.type = type;
            }

            public Builder WithParallelism(int parallelism)
            {
                this.parallelism = parallelism;
                return this;
            }

            public Builder WithSalt(byte[] salt)
            {
                this.salt = Arrays.Clone(salt);
                return this;
            }

            public Builder WithSecret(byte[] secret)
            {
                this.secret = Arrays.Clone(secret);
                return this;
            }

            public Builder WithAdditional(byte[] additional)
            {
                this.additional = Arrays.Clone(additional);
                return this;
            }

            public Builder WithIterations(int iterations)
            {
                this.iterations = iterations;
                return this;
            }

            public Builder WithMemoryAsKB(int memory)
            {
                this.memory = memory;
                return this;
            }

            public Builder WithMemoryPowOfTwo(int memory)
            {
                this.memory = 1 << memory;
                return this;
            }

            public Builder WithVersion(int version)
            {
                this.version = version;
                return this;
            }

            public Builder WithCharToByteConverter(ICharToByteConverter converter)
            {
                this.converter = converter;
                return this;
            }

            public Argon2Parameters Build() =>
                new Argon2Parameters(type, salt, secret, additional, iterations, memory, parallelism, version, converter);

            public void Clear()
            {
                Arrays.Clear(salt);
                Arrays.Clear(secret);
                Arrays.Clear(additional);
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

        public ICharToByteConverter CharToByteConverter => converter;

        public byte[] GetSalt() => Arrays.Clone(salt);

        public byte[] GetSecret() => Arrays.Clone(secret);

        public byte[] GetAdditional() => Arrays.Clone(additional);

        public int Iterations => iterations;

        public int Parallelism => parallelism;

        public int Memory => memory;

        public int Type => type;

        public int Version => version;

        internal byte[] Additional => additional;

        internal byte[] Salt => salt;

        internal byte[] Secret => secret;
    }
}
