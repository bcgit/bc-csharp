using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class Argon2Parameters
    {
        public const int ARGON2_d = 0x00;
        public const int ARGON2_i = 0x01;
        public const int ARGON2_id = 0x02;

        public const int ARGON2_VERSION_10 = 0x10;
        public const int ARGON2_VERSION_13 = 0x13;

        private readonly byte[] salt;
        private readonly byte[] secret;
        private readonly byte[] additional;

        private readonly int iterations;
        private readonly int memory;
        private readonly int lanes;

        private readonly int version;
        private readonly int type;
        private readonly ICharToByteConverter converter;

        public class Builder
        {
            private const int DEFAULT_ITERATIONS = 3;
            private const int DEFAULT_MEMORY_COST = 12;
            private const int DEFAULT_LANES = 1;
            private const int DEFAULT_TYPE = ARGON2_i;
            private const int DEFAULT_VERSION = ARGON2_VERSION_13;

            private byte[] salt = Array.Empty<byte>();
            private byte[] secret = Array.Empty<byte>();
            private byte[] additional = Array.Empty<byte>();

            private int iterations;
            private int memory;
            private int lanes;

            private int version;
            private readonly int type;

            private ICharToByteConverter converter = PasswordConverter.UTF8;

            public Builder()
                : this(DEFAULT_TYPE)
            {
            }

            public Builder(int type)
            {
                this.type = type;
                lanes = DEFAULT_LANES;
                memory = 1 << DEFAULT_MEMORY_COST;
                iterations = DEFAULT_ITERATIONS;
                version = DEFAULT_VERSION;
            }

            public Builder WithParallelism(int parallelism)
            {
                lanes = parallelism;
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

            public Builder WithCharToByteConverter(string name, Func<char[], byte[]> converterFunction)
            {
                return WithCharToByteConverter(new PasswordConverter(name, converterFunction));
            }

            public Builder WithCharToByteConverter(Func<char[], byte[]> converterFunction)
            {
                return WithCharToByteConverter("Custom", converterFunction);
            }

            public Argon2Parameters Build()
            {
                return new Argon2Parameters(type, salt, secret, additional, iterations, memory, lanes, version, converter);
            }

            public void Clear()
            {
                Arrays.Clear(salt);
                Arrays.Clear(secret);
                Arrays.Clear(additional);
            }
        }

        private Argon2Parameters(
            int type,
            byte[] salt,
            byte[] secret,
            byte[] additional,
            int iterations,
            int memory,
            int lanes,
            int version,
            ICharToByteConverter converter)
        {

            this.salt = Arrays.Clone(salt);
            this.secret = Arrays.Clone(secret);
            this.additional = Arrays.Clone(additional);
            this.iterations = iterations;
            this.memory = memory;
            this.lanes = lanes;
            this.version = version;
            this.type = type;
            this.converter = converter;
        }

        public byte[] GetSalt()
        {
            return Arrays.Clone(salt);
        }

        public byte[] GetSecret()
        {
            return Arrays.Clone(secret);
        }

        public byte[] GetAdditional()
        {
            return Arrays.Clone(additional);
        }

        public int GetIterations()
        {
            return iterations;
        }

        public int GetMemory()
        {
            return memory;
        }

        public int GetLanes()
        {
            return lanes;
        }

        public int GetVersion()
        {
            return version;
        }

        public int GetArgonType()
        {
            return type;
        }

        public ICharToByteConverter GetCharToByteConverter()
        {
            return converter;
        }

    }
}
