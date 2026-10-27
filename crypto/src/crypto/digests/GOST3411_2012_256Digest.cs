using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>The GOST R 34.11-2012 (Streebog) hash function with a 256-bit output.</summary>
    public class Gost3411_2012_256Digest : Gost3411_2012Digest
    {
        private readonly static byte[] IV = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        /// <inheritdoc/>
        public override string AlgorithmName
        {
            get { return "GOST3411-2012-256"; }
        }

        /// <summary>Create a new <see cref="Gost3411_2012_256Digest"/>.</summary>
        public Gost3411_2012_256Digest() : base(IV)
        {

        }

        /// <summary>Create a copy of the given <see cref="Gost3411_2012_256Digest"/>.</summary>
        /// <param name="other">The instance to copy.</param>
        public Gost3411_2012_256Digest(Gost3411_2012_256Digest other) : base(IV)
        {
            Reset(other);
        }

        /// <inheritdoc/>
        public override int GetDigestSize()
        {
            return 32;
        }

        /// <inheritdoc/>
        public override int DoFinal(byte[] output, int outOff)
        {
            byte[] result = new byte[64];
            base.DoFinal(result, 0);

            Array.Copy(result, 32, output, outOff, 32);

            return 32;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int DoFinal(Span<byte> output)
        {
            Span<byte> result = stackalloc byte[64];
            base.DoFinal(result);

            result[32..].CopyTo(output);

            return 32;
        }
#endif

        /// <inheritdoc/>
        public override IMemoable Copy()
        {
            return new Gost3411_2012_256Digest(this);
        }
    }
}
