using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>The GOST R 34.11-2012 (Streebog) hash function with a 512-bit output.</summary>
    public class Gost3411_2012_512Digest:Gost3411_2012Digest
    {
        private readonly static byte[] IV = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

        /// <inheritdoc/>
        public override string AlgorithmName
        {
            get { return "GOST3411-2012-512"; }
        }

        /// <summary>Create a new <see cref="Gost3411_2012_512Digest"/>.</summary>
        public Gost3411_2012_512Digest():base(IV)
        {
        }

        /// <summary>Create a copy of the given <see cref="Gost3411_2012_512Digest"/>.</summary>
        /// <param name="other">The instance to copy.</param>
        public Gost3411_2012_512Digest(Gost3411_2012_512Digest other) : base(IV)
        {
            Reset(other);
        }

        /// <inheritdoc/>
        public override int GetDigestSize()
        {
            return 64;
        }

        /// <inheritdoc/>
        public override IMemoable Copy()
        {
            return new Gost3411_2012_512Digest(this);
        }
    }
}
