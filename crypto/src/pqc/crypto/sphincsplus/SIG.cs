using System;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class SIG
    {
        private readonly byte[] r;
        private readonly SIG_FORS[] sig_fors;
        private readonly SIG_XMSS[] sig_ht;

        internal SIG(SphincsPlusEngine engine, byte[] signature)
        {
            int n = engine.N;
            int k = engine.K;
            int a = engine.A;
            uint d = engine.D;
            uint hPrime = engine.H_PRIME;
            int wots_len = engine.WOTS_LEN;

            this.r = new byte[n];
            Array.Copy(signature, 0, r, 0, n);

            this.sig_fors = new SIG_FORS[k];
            int offset = n;
            for (int i = 0; i != k; i++)
            {
                byte[] sk = new byte[n];
                Array.Copy(signature, offset, sk, 0, n);
                offset += n;
                byte[][] authPath = new byte[a][];
                for (int j = 0; j != a; j++)
                {
                    authPath[j] = new byte[n];
                    Array.Copy(signature, offset, authPath[j], 0, n);
                    offset += n;
                }

                sig_fors[i] = new SIG_FORS(sk, authPath);
            }

            sig_ht = new SIG_XMSS[d];
            for (int i = 0; i != d; i++)
            {
                byte[] sig = new byte[wots_len * n];
                Array.Copy(signature, offset, sig, 0, sig.Length);
                offset += sig.Length;
                byte[][] authPath = new byte[hPrime][];
                for (int j = 0; j != hPrime; j++)
                {
                    authPath[j] = new byte[n];
                    Array.Copy(signature, offset, authPath[j], 0, n);
                    offset += n;
                }

                sig_ht[i] = new SIG_XMSS(sig, authPath);
            }

            if (offset != signature.Length)
                throw new ArgumentException("signature wrong length");
        }

        public byte[] R => r;

        public SIG_FORS[] SIG_FORS => sig_fors;

        public SIG_XMSS[] SIG_HT => sig_ht;
    }
}
