using System;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class SIG_FORS
    {
        internal byte[][] authPath;
        internal byte[] sk;

        internal SIG_FORS(byte[] sk, byte[][] authPath)
        {
            this.authPath = authPath;
            this.sk = sk;
        }

        internal void CopyToSignature(byte[] signature, ref int pos)
        {
            Array.Copy(sk, 0, signature, pos, sk.Length);
            pos += sk.Length;

            for (int i = 0; i < authPath.Length; ++i)
            {
                Array.Copy(authPath[i], 0, signature, pos, authPath[i].Length);
                pos += authPath[i].Length;
            }
        }

        internal byte[] SK => sk;

        internal byte[][] AuthPath => authPath;
    }
}
