using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>The string to key specifier class.</remarks>
    public class S2k
        : BcpgObject
    {
        /// <summary>Generate a salted string-to-key specifier.</summary>
        /// <param name="secureRandom">The source of randomness for the salt.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>The specifier.</returns>
        public static S2k GenerateSalted(SecureRandom secureRandom, HashAlgorithmTag hashAlgorithm)
        {
            var iv = GenerateIV(secureRandom);
            return new S2k(hashAlgorithm, iv);
        }

        /// <summary>Generate an iterated and salted string-to-key specifier.</summary>
        /// <param name="secureRandom">The source of randomness for the salt.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="itCount">The iteration count.</param>
        /// <returns>The specifier.</returns>
        public static S2k GenerateSaltedAndIterated(SecureRandom secureRandom, HashAlgorithmTag hashAlgorithm,
            int itCount)
        {
            if (itCount < 0x00 || itCount > 0xFF)
                throw new ArgumentOutOfRangeException(nameof(itCount), "Coded S2K iteration count must be in range 0-255");

            var iv = GenerateIV(secureRandom);
            return new S2k(hashAlgorithm, iv, itCount);
        }

        private const int ExpBias = 6;

        /// <summary>Simple key generation. A single non-salted iteration of a hash function.</summary>
        /// <remarks>
        /// This method is deprecated to use, since it can be brute-forced when used with a low-entropy string, such as
        /// those typically provided by users. Additionally, the usage of Simple S2K can lead to key and IV reuse.
        /// Therefore, in OpenPGP v6, when generating an S2K specifier, an implementation MUST NOT use Simple S2K.
        /// </remarks>
        public const int Simple = 0;

        /// <summary>Salted key generation. A single iteration of a hash function with a (unique) salt.</summary>
        /// <remarks>
        /// This method is deprecated to use, since it can be brute-forced when used with a low-entropy string, such as
        /// those typically provided by users. Therefore, in OpenPGP v6, an implementation SHOULD NOT generate a Salted
        /// S2K, unless the implementation knows that the input string is high-entropy.
        /// </remarks>
        public const int Salted = 1;

        /// <summary>Salted and iterated key generation. Multiple iterations of a hash function, with a salt.</summary>
        /// <remarks>This method MAY be used if <see cref="Argon2"/> is not available.</remarks>
        public const int SaltedAndIterated = 3;

        /// <summary>Memory-hard, salted key generation using Argon2 hash algorithm.</summary>
        public const int Argon2 = 4;

        /// <summary>The <c>GnuDummyS2K</c> constant, with the value <c>101</c>.</summary>
        public const int GnuDummyS2K = 101;
        /// <summary>The <c>GnuProtectionModeNoPrivateKey</c> constant, with the value <c>1</c>.</summary>
        public const int GnuProtectionModeNoPrivateKey = 1;
        /// <summary>The <c>GnuProtectionModeDivertToCard</c> constant, with the value <c>2</c>.</summary>
        public const int GnuProtectionModeDivertToCard = 2;
        /// <summary>The <c>GnuProtectionModeInternal</c> constant, with the value <c>3</c>.</summary>
        public const int GnuProtectionModeInternal = 3;

        internal int m_type;
        internal HashAlgorithmTag m_algorithm;
        internal byte[] m_iv;
        internal int m_itCount = -1;
        internal int m_protectionMode = -1;
        internal Argon2Params m_argon2Config;

        internal S2k(Stream inStr)
        {
            m_type = StreamUtilities.RequireByte(inStr);

            switch (m_type)
            {
            case Simple:
            {
                m_algorithm = (HashAlgorithmTag)StreamUtilities.RequireByte(inStr);
                break;
            }
            case Salted:
            {
                m_algorithm = (HashAlgorithmTag)StreamUtilities.RequireByte(inStr);
                m_iv = StreamUtilities.RequireBytes(inStr, 8);
                break;
            }
            case SaltedAndIterated:
            {
                m_algorithm = (HashAlgorithmTag)StreamUtilities.RequireByte(inStr);
                m_iv = StreamUtilities.RequireBytes(inStr, 8);
                m_itCount = StreamUtilities.RequireByte(inStr);
                break;
            }
            case Argon2:
            {
                byte[] salt = StreamUtilities.RequireBytes(inStr, 16);
                byte passes = StreamUtilities.RequireByte(inStr);
                byte parallelism = StreamUtilities.RequireByte(inStr);
                byte memorySizeExponent = StreamUtilities.RequireByte(inStr);
                m_argon2Config = new Argon2Params(salt, passes, parallelism, memorySizeExponent);
                break;
            }
            case GnuDummyS2K:
            {
                m_algorithm = (HashAlgorithmTag)StreamUtilities.RequireByte(inStr);
                uint GNU_ = StreamUtilities.RequireUInt32BE(inStr);
                m_protectionMode = (byte)GNU_;
                break;
            }
            default:
                throw new UnsupportedPacketVersionException("Invalid S2K type: " + m_type);
            }
        }

        /// <summary>Create a new <see cref="S2k"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        public S2k(HashAlgorithmTag algorithm)
        {
            m_type = Simple;
            m_algorithm = algorithm;
        }

        /// <summary>Create a new <see cref="S2k"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="iv">The initialization vector.</param>
        public S2k(HashAlgorithmTag algorithm, byte[] iv)
        {
            m_type = Salted;
            m_algorithm = algorithm;
            m_iv = iv;
        }

        /// <summary>Create a new <see cref="S2k"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="itCount">The it count.</param>
        public S2k(HashAlgorithmTag algorithm, byte[] iv, int itCount)
        {
            m_type = SaltedAndIterated;
            m_algorithm = algorithm;
            m_iv = iv;
            m_itCount = itCount;
        }

        /// <summary>Create a new <see cref="S2k"/>.</summary>
        /// <param name="argon2Config">The argon 2 config.</param>
        public S2k(Argon2Params argon2Config)
        {
            m_type = Argon2;
            m_argon2Config = argon2Config ?? throw new ArgumentNullException(nameof(argon2Config));
        }

        /// <summary>Create an Argon2 string-to-key specifier.</summary>
        /// <param name="parameters">The Argon2 parameters.</param>
        /// <returns>The specifier.</returns>
        public static S2k Argon2S2k(Argon2Params parameters) => new S2k(parameters);

        /// <summary>Gets the type.</summary>
        public virtual int Type => m_type;

        /// <summary>The hash algorithm.</summary>
        public virtual HashAlgorithmTag HashAlgorithm => m_algorithm;

        /// <summary>The IV for the key generation algorithm.</summary>
        public virtual byte[] GetIV() => Arrays.Clone(m_iv);

        /// <summary>The iteration count</summary>
        public virtual long IterationCount => m_itCount >= 256 ? m_itCount : DeriveIterationCount(m_itCount);

        /// <summary>The protection mode - only if GnuDummyS2K</summary>
        public virtual int ProtectionMode => m_protectionMode;

        /// <summary>Gets the argon 2 config.</summary>
        public virtual Argon2Params Argon2Config => m_argon2Config;

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WriteByte((byte)m_type);

            switch (m_type)
            {
            case Simple:
            {
                bcpgOut.WriteByte((byte)m_algorithm);
                break;
            }
            case Salted:
            {
                bcpgOut.WriteByte((byte)m_algorithm);
                bcpgOut.Write(m_iv);
                break;
            }
            case SaltedAndIterated:
            {
                bcpgOut.WriteByte((byte)m_algorithm);
                bcpgOut.Write(m_iv);
                WriteCheckedByte(bcpgOut, m_itCount, "Iteration count");
                break;
            }
            case Argon2:
            {
                bcpgOut.Write(m_argon2Config.GetSalt());
                WriteCheckedByte(bcpgOut, m_argon2Config.Passes, "Passes");
                WriteCheckedByte(bcpgOut, m_argon2Config.Parallelism, "Parallelism");
                WriteCheckedByte(bcpgOut, m_argon2Config.MemorySizeExponent, "Memory size exponent");
                break;
            }
            case GnuDummyS2K:
            {
                bcpgOut.Write((byte)m_algorithm, (byte)'G', (byte)'N', (byte)'U', (byte)m_protectionMode);
                break;
            }
            default:
                throw new InvalidOperationException("Unknown S2K type " + m_type);
            }
        }

        private static long DeriveIterationCount(int itCount) => (16 + (itCount & 15)) << ((itCount >> 4) + ExpBias);

        private static byte[] GenerateIV(SecureRandom secureRandom) => SecureRandom.GetNextBytes(secureRandom, 8);

        private static void WriteCheckedByte(BcpgOutputStream bcpgOut, int val, string valName)
        {
            if ((val & 0xFFFFFF00) != 0)
                throw new InvalidOperationException(valName + " not encodable");

            bcpgOut.WriteByte((byte)val);
        }

        /// <summary>
        /// The parameters of the Argon2 string-to-key specifier: passes, parallelism, memory size and salt.
        /// </summary>
        public sealed class Argon2Params
        {
            /// <summary>Get the default source of randomness.</summary>
            /// <returns>The source of randomness.</returns>
            public static SecureRandom DefaultSecureRandom() => CryptoServicesRegistrar.GetSecureRandom();

            /// <summary>
            /// Get the recommended parameters for memory-constrained environments (RFC 9106 section 4, second
            /// recommended option).
            /// </summary>
            /// <param name="secureRandom">The source of randomness for the salt.</param>
            /// <returns>The parameters.</returns>
            public static Argon2Params MemoryConstrainedParameters(SecureRandom secureRandom) =>
                new Argon2Params(3, 4, 16, secureRandom);

            /// <summary>Get the recommended parameters (RFC 9106 section 4, first recommended option).</summary>
            /// <param name="secureRandom">The source of randomness for the salt.</param>
            /// <returns>The parameters.</returns>
            public static Argon2Params RecommendedParameters(SecureRandom secureRandom) =>
                new Argon2Params(1, 4, 21, secureRandom);

            private readonly byte[] m_salt;
            private readonly int m_passes;
            private readonly int m_parallelism;
            private readonly int m_memorySizeExponent;

            /// <summary>Create a new <see cref="Argon2Params"/>.</summary>
            /// <param name="passes">The passes.</param>
            /// <param name="parallelism">The parallelism.</param>
            /// <param name="memorySizeExponent">The memory size exponent.</param>
            /// <param name="secureRandom">The source of randomness.</param>
            public Argon2Params(int passes, int parallelism, int memorySizeExponent, SecureRandom secureRandom)
                : this(salt: GenerateSalt(secureRandom), passes, parallelism, memorySizeExponent)
            {
            }

            /// <summary>Create a new <see cref="Argon2Params"/>.</summary>
            /// <param name="salt">The salt.</param>
            /// <param name="passes">The passes.</param>
            /// <param name="parallelism">The parallelism.</param>
            /// <param name="memorySizeExponent">The memory size exponent.</param>
            public Argon2Params(byte[] salt, int passes, int parallelism, int memorySizeExponent)
            {
                // See RFC 9580 3.7.1.4

                if (salt.Length != 16)
                    throw new ArgumentException("Argon2 uses 16 bytes of salt", nameof(salt));
                if (passes < 1 || passes > 255)
                    throw new ArgumentOutOfRangeException(nameof(passes), passes,
                        "MUST be an integer value from 1 to 255.");
                if (parallelism < 1 || parallelism > 255)
                    throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism,
                        "MUST be an integer value from 1 to 255.");

                /*
                 * Memory size (i.e. 1 << memorySizeExponent) MUST be an integer number of kibibytes from 8*p to 2^32-1.
                 * Max here is 30 because we are treating memory size as a signed 32-bit value.
                 */
                int minExp = 3 + Integers.BitLength(parallelism - 1);
                int maxExp = 30;
                if (memorySizeExponent < minExp || memorySizeExponent > maxExp)
                    throw new ArgumentOutOfRangeException(nameof(memorySizeExponent), memorySizeExponent,
                        "MUST be an integer value from 3 + bitlen(parallelism - 1) to 30.");

                m_salt = Arrays.Clone(salt);
                m_passes = passes;
                m_parallelism = parallelism;
                m_memorySizeExponent = memorySizeExponent;
            }

            /// <summary>Return the salt.</summary>
            public byte[] GetSalt() => Arrays.Clone(m_salt);

            /// <summary>Gets the memory size exponent.</summary>
            public int MemorySizeExponent => m_memorySizeExponent;

            /// <summary>Gets the parallelism.</summary>
            public int Parallelism => m_parallelism;

            /// <summary>Gets the passes.</summary>
            public int Passes => m_passes;

            private static byte[] GenerateSalt(SecureRandom secureRandom) =>
                SecureRandom.GetNextBytes(secureRandom, 16);
        }
    }
}
