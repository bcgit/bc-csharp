using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
     */
    public class HMacDsaKCalculator
        :   IDsaKCalculator
    {
        private readonly HMac hMac;
        private readonly byte[] K;
        private readonly byte[] V;

        private BigInteger n;

        /**
         * Base constructor.
         *
         * @param digest digest to build the HMAC on.
         */
        public HMacDsaKCalculator(IDigest digest)
        {
            this.hMac = new HMac(digest);
            this.V = new byte[hMac.GetMacSize()];
            this.K = new byte[hMac.GetMacSize()];
        }

        public virtual bool IsDeterministic
        {
            get { return true; }
        }

        public virtual void Init(BigInteger n, SecureRandom random)
        {
            throw new InvalidOperationException("Operation not supported");
        }

        public void Init(BigInteger n, BigInteger d, byte[] message)
        {
            this.n = n;

            Arrays.Fill(V, 0x01);
            Arrays.Fill(K, 0);

            BigInteger mInt = BitsToInt(message);
            if (mInt.CompareTo(n) >= 0)
            {
                mInt = mInt.Subtract(n);
            }

            int size = BigIntegers.GetUnsignedByteLength(n);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int xmSize = size * 2;
            Span<byte> xm = xmSize <= 512
                ? stackalloc byte[xmSize]
                : new byte[xmSize];
            BigIntegers.AsUnsignedByteArray(d, xm[..size]);
            BigIntegers.AsUnsignedByteArray(mInt, xm[size..]);
#else
            byte[] x = BigIntegers.AsUnsignedByteArray(size, d);
            byte[] m = BigIntegers.AsUnsignedByteArray(size, mInt);
#endif

            hMac.Init(new KeyParameter(K));

            hMac.BlockUpdate(V, 0, V.Length);
            hMac.Update(0x00);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            hMac.BlockUpdate(xm);
#else
            hMac.BlockUpdate(x, 0, x.Length);
            hMac.BlockUpdate(m, 0, m.Length);
#endif
            InitAdditionalInput0(hMac);
            hMac.DoFinal(K, 0);

            hMac.Init(new KeyParameter(K));
            hMac.BlockUpdate(V, 0, V.Length);
            hMac.DoFinal(V, 0);

            hMac.BlockUpdate(V, 0, V.Length);
            hMac.Update(0x01);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            hMac.BlockUpdate(xm);
#else
            hMac.BlockUpdate(x, 0, x.Length);
            hMac.BlockUpdate(m, 0, m.Length);
#endif
            InitAdditionalInput1(hMac);
            hMac.DoFinal(K, 0);

            hMac.Init(new KeyParameter(K));
            hMac.BlockUpdate(V, 0, V.Length);
            hMac.DoFinal(V, 0);
        }

        public virtual BigInteger NextK()
        {
            byte[] t = new byte[BigIntegers.GetUnsignedByteLength(n)];

            for (;;)
            {
                int tOff = 0;

                while (tOff < t.Length)
                {
                    hMac.BlockUpdate(V, 0, V.Length);
                    hMac.DoFinal(V, 0);

                    int len = System.Math.Min(t.Length - tOff, V.Length);
                    Array.Copy(V, 0, t, tOff, len);
                    tOff += len;
                }

                BigInteger k = BitsToInt(t);

                if (k.SignValue > 0 && k.CompareTo(n) < 0)
                    return k;

                hMac.BlockUpdate(V, 0, V.Length);
                hMac.Update(0x00);
                hMac.DoFinal(K, 0);

                hMac.Init(new KeyParameter(K));
                hMac.BlockUpdate(V, 0, V.Length);
                hMac.DoFinal(V, 0);
            }
        }

        /// <summary>Supply additional input to HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)).</summary>
        /// <remarks>
        /// RFC 6979 3.6. Additional data may be added to the input of HMAC [..]. A use case may be a protocol that
        /// requires a non-deterministic signature algorithm on a system that does not have access to a high-quality
        /// random source. It suffices that the additional data[..] is non-repeating(e.g., a signature counter or a
        /// monotonic clock) to ensure "random-looking" signatures are indistinguishable, in a cryptographic way, from
        /// plain (EC)DSA signatures.
        /// <para/>
        /// By default there is no additional input. Override this method to supply additional input, bearing in mind
        /// that this calculator may be used for many signatures.
        /// </remarks>
        /// <param name="hmac0">The <see cref="HMac"/> to which the additional input should be added.</param>
        protected virtual void InitAdditionalInput0(HMac hmac0)
        {
        }

        /// <summary>Supply additional input to HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)).</summary>
        /// <remarks>
        /// Refer to comments for <see cref="InitAdditionalInput0(HMac)"/>.
        /// </remarks>
        /// <param name="hmac1">The <see cref="HMac"/> to which the additional input should be added.</param>
        protected virtual void InitAdditionalInput1(HMac hmac1)
        {
        }

        private BigInteger BitsToInt(byte[] t)
        {
            BigInteger v = new BigInteger(1, t);

            if (t.Length * 8 > n.BitLength)
            {
                v = v.ShiftRight(t.Length * 8 - n.BitLength);
            }

            return v;
        }
    }
}
