using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>The string to key specifier class.</remarks>
    public class S2k
        : BcpgObject
    {
        private const int ExpBias = 6;

        public const int Simple = 0;
        public const int Salted = 1;
        public const int SaltedAndIterated = 3;
        public const int Argon2 = 4;
        public const int GnuDummyS2K = 101;
        public const int GnuProtectionModeNoPrivateKey = 1;
        public const int GnuProtectionModeDivertToCard = 2;

        private readonly int type;
        private readonly HashAlgorithmTag algorithm;
        private readonly byte[] iv;
        
        private readonly int itCount = -1;
        private readonly int protectionMode = -1;

        // params for Argon2
        private readonly int passes;
        private readonly int parallelism;
        private readonly int memorySizeExponent;

        internal S2k(
            Stream inStr)
        {
			type = inStr.ReadByte();

            switch (type)
            {
                case Simple:
                    algorithm = (HashAlgorithmTag)inStr.ReadByte();
                    break;

                case Salted:
                    algorithm = (HashAlgorithmTag)inStr.ReadByte();
                    iv = new byte[8];
                    Streams.ReadFully(inStr, iv);
                    break;

                case SaltedAndIterated:
                    algorithm = (HashAlgorithmTag)inStr.ReadByte();
                    iv = new byte[8];
                    Streams.ReadFully(inStr, iv);
                    itCount = inStr.ReadByte();
                    break;

                case Argon2:
                    iv = new byte[16];
                    Streams.ReadFully(inStr, iv);
                    passes = inStr.ReadByte();
                    parallelism = inStr.ReadByte();
                    memorySizeExponent = inStr.ReadByte();
                    break;

                case GnuDummyS2K:
                    algorithm = (HashAlgorithmTag)inStr.ReadByte();
                    inStr.ReadByte(); // G
                    inStr.ReadByte(); // N
                    inStr.ReadByte(); // U
                    protectionMode = inStr.ReadByte(); // protection mode
                    break;

                default:
                    throw new UnsupportedPacketVersionException($"Invalid S2K type: {type}");
            }

        }

        /// <summary>Constructs a specifier for a simple S2K generation</summary>
        /// <param name="algorithm">the digest algorithm to use.</param>
        public S2k(
            HashAlgorithmTag algorithm)
        {
            this.type = Simple;
            this.algorithm = algorithm;
        }

        /// <summary>Constructs a specifier for a salted S2K generation</summary>
        /// <param name="algorithm">the digest algorithm to use.</param>
        /// <param name="iv">the salt to apply to input to the key generation</param>
        public S2k(
            HashAlgorithmTag algorithm,
            byte[] iv)
        {
            this.type = Salted;
            this.algorithm = algorithm;
            this.iv = Arrays.Clone(iv);
        }

        /// <summary>Constructs a specifier for a salted and iterated S2K generation</summary>
        /// <param name="algorithm">the digest algorithm to iterate.</param>
        /// <param name="iv">the salt to apply to input to the key generation</param>
        /// <param name="itCount">the single byte iteration count specifier</param>
        public S2k(
            HashAlgorithmTag algorithm,
            byte[] iv,
            int itCount)
        {
            this.type = SaltedAndIterated;
            this.algorithm = algorithm;
            this.iv = Arrays.Clone(iv);
            this.itCount = itCount;
        }

        /// <summary>Constructs a specifier for an S2K method using Argon2</summary>
        public S2k(byte[] salt, int passes, int parallelism, int memorySizeExponent)
        {
            this.type = Argon2;
            this.iv = Arrays.Clone(salt);
            this.passes = passes;
            this.parallelism = parallelism;
            this.memorySizeExponent = memorySizeExponent;
        }

        /// <summary>Constructs a specifier for an S2K method using Argon2</summary>
        public S2k(Argon2Parameters argon2Params)
            :this(argon2Params.Salt, argon2Params.Passes, argon2Params.Parallelism, argon2Params.MemSizeExp)
        {
        }

        public virtual int Type
        {
			get { return type; }
        }

		/// <summary>The hash algorithm.</summary>
        public virtual HashAlgorithmTag HashAlgorithm
        {
			get { return algorithm; }
		}

		/// <summary>The IV for the key generation algorithm.</summary>
        public virtual byte[] GetIV()
        {
            return Arrays.Clone(iv);
        }

		/// <summary>The iteration count</summary>
        public virtual long IterationCount
		{
			get { return (16 + (itCount & 15)) << ((itCount >> 4) + ExpBias); }
		}

		/// <summary>The protection mode - only if GnuDummyS2K</summary>
        public virtual int ProtectionMode
        {
			get { return protectionMode; }
        }

        /// <summary>The number of passes - only if Argon2</summary>
        public int Passes
        {
            get { return passes; }
        }

        /// <summary>The degree of parallelism - only if Argon2</summary>
        public int Parallelism
        {
            get { return parallelism; }
        }

        /// <summary>The memory size exponent - only if Argon2</summary>
        public int MemorySizeExponent
        {
            get { return memorySizeExponent; }
        }
        
        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            switch (type)
            {
                case Simple:
                    bcpgOut.WriteByte((byte)type);
                    bcpgOut.WriteByte((byte)algorithm);
                    break;

                case Salted:
                    bcpgOut.WriteByte((byte)type);
                    bcpgOut.WriteByte((byte)algorithm);
                    bcpgOut.Write(iv);
                    break;

                case SaltedAndIterated:
                    bcpgOut.WriteByte((byte)type);
                    bcpgOut.WriteByte((byte)algorithm);
                    bcpgOut.Write(iv);
                    bcpgOut.WriteByte((byte)itCount);
                    break;

                case Argon2:
                    bcpgOut.WriteByte((byte)type);
                    bcpgOut.Write(iv);
                    bcpgOut.WriteByte((byte)passes);
                    bcpgOut.WriteByte((byte)parallelism);
                    bcpgOut.WriteByte((byte)memorySizeExponent);
                    break;

                case GnuDummyS2K:
                    bcpgOut.WriteByte((byte)type);
                    bcpgOut.WriteByte((byte)algorithm);
                    bcpgOut.WriteByte((byte)'G');
                    bcpgOut.WriteByte((byte)'N');
                    bcpgOut.WriteByte((byte)'U');
                    bcpgOut.WriteByte((byte)protectionMode);
                    break;

                default:
                    throw new InvalidOperationException($"Unknown S2K type {type}");
            }
        }

        /// <summary>
        /// Parameters for Argon2 S2K
        /// <see href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#s2k-argon2">Sect. 3.7.1.4 of crypto-refresh</see>see>
        /// </summary>
        public class Argon2Parameters
        {
            private readonly byte[] salt;
            private readonly int passes;
            private readonly int parallelism;
            private readonly int memSizeExp;

            internal byte[] Salt => salt;
            internal int Passes => passes;
            internal int Parallelism => parallelism;
            internal int MemSizeExp => memSizeExp;

            /// <summary>
            /// Uniformly safe and recommended parameters not tailored to any hardware.
            /// Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
            /// <see href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1"> RFC 9106: §4. Parameter Choice</see>
            /// </summary>
            public Argon2Parameters()
                :this (CryptoServicesRegistrar.GetSecureRandom())
            {
            }


            /// <summary>
            /// Uniformly safe and recommended parameters not tailored to any hardware.
            /// Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
            /// <see href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1"> RFC 9106: §4. Parameter Choice</see>
            /// </summary>
            /// <param name="secureRandom"></param>
            public Argon2Parameters(SecureRandom secureRandom)
                : this(1, 4, 21, secureRandom)
            {
            }

            /// <summary>
            /// Create customized Argon2 S2K parameters.
            /// </summary>
            /// <param name="passes">number of iterations, must be greater than 0</param>
            /// <param name="parallelism">number of lanes, must be greater 0</param>
            /// <param name="memSizeExp">exponent for memory consumption, must be between 3+ceil(log_2(p)) and 31</param>
            /// <param name="secureRandom">A secure random generator</param>
            /// <exception cref="ArgumentException"></exception>
            public Argon2Parameters(int passes, int parallelism, int memSizeExp, SecureRandom secureRandom)
                :this(GenerateSalt(secureRandom), passes, parallelism, memSizeExp)
            {
            }

            /// <summary>
            /// Create customized Argon2 S2K parameters.
            /// </summary>
            /// <param name="salt">16 bytes of random salt</param>
            /// <param name="passes">number of iterations, must be greater than 0</param>
            /// <param name="parallelism">number of lanes, must be greater 0</param>
            /// <param name="memSizeExp">exponent for memory consumption, must be between 3+ceil(log_2(p)) and 31</param>
            /// <exception cref="ArgumentException"></exception>
            public Argon2Parameters(byte[] salt, int passes, int parallelism, int memSizeExp)
            {
                if (salt.Length != 16)
                {
                    throw new ArgumentException("Argon2 uses 16 bytes of salt");
                }
                this.salt = salt;

                if (passes < 1)
                {
                    throw new ArgumentException("Number of passes MUST be positive, non-zero");
                }
                this.passes = passes;

                if (parallelism < 1)
                {
                    throw new ArgumentException("Parallelism MUST be positive, non-zero.");
                }
                this.parallelism = parallelism;

                // log_2(p) = log_e(p) / log_e(2)
                double log2_p = System.Math.Log(parallelism) / System.Math.Log(2);
                // see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-argon2
                if (memSizeExp < (3 + System.Math.Ceiling(log2_p)) || memSizeExp > 31)
                {
                    throw new ArgumentException("Memory size exponent MUST be between 3+ceil(log_2(parallelism)) and 31");
                }
                this.memSizeExp = memSizeExp;
            }
            
            /// <summary>
            /// Uniformly safe and recommended parameters not tailored to any hardware.
            /// Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
            /// <see href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1"> RFC 9106: §4. Parameter Choice</see>
            /// </summary>
            public static Argon2Parameters UniversallyRecommendedParameters()
            {
                return new Argon2Parameters(1, 4, 21, CryptoServicesRegistrar.GetSecureRandom());
            }

            /// <summary>
            /// Recommended parameters for memory constrained environments(64MiB RAM).
            /// Uses Argon2id with 3 passes, 4 lanes and 64 MiB RAM.
            /// <see href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1"> RFC 9106: §4. Parameter Choice</see>
            /// </summary>
            public static Argon2Parameters MemoryConstrainedParameters()
            {
                return new Argon2Parameters(3, 4, 16, CryptoServicesRegistrar.GetSecureRandom());
            }

            private static byte[] GenerateSalt(SecureRandom secureRandom)
            {
                byte[] salt = new byte[16];
                secureRandom.NextBytes(salt);
                return salt;
            }
        }
    }
}
