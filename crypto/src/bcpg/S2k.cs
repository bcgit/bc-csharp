using System;
using System.IO;
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
    }
}
