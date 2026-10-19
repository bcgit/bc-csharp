using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>A source of the per-signature value k for DSA that uses random numbers.</summary>
    public class RandomDsaKCalculator
        :   IDsaKCalculator
    {
        private BigInteger q;
        private SecureRandom random;

        /// <inheritdoc/>
        public virtual bool IsDeterministic
        {
            get { return false; }
        }

        /// <inheritdoc/>
        public virtual void Init(BigInteger n, SecureRandom random)
        {
            this.q = n;
            this.random = random;
        }

        /// <inheritdoc/>
        public virtual void Init(BigInteger n, BigInteger d, byte[] message)
        {
            throw new InvalidOperationException("Operation not supported");
        }

        /// <inheritdoc/>
        public virtual BigInteger NextK()
        {
            int qBitLength = q.BitLength;

            BigInteger k;
            do
            {
                k = new BigInteger(qBitLength, random);
            }
            while (k.SignValue < 1 || k.CompareTo(q) >= 0);

            return k;
        }
    }
}
