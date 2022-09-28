using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal static class Symmetric
    {
        internal const int Shake128Rate = 168;

        internal static void Prf(byte[] outbuf, int outlen, byte[] key, byte nonce)
        {
            ShakeDigest shake256 = new ShakeDigest(256);
            shake256.BlockUpdate(key, 0, KyberEngine.SymBytes);
            shake256.Update(nonce);
            shake256.DoFinal(outbuf, 0, outlen);
        }

        internal static ShakeDigest Xof(byte[] seed, byte a, byte b)
        {
            ShakeDigest shake128 = new ShakeDigest(128);
            shake128.BlockUpdate(seed, 0, seed.Length);
            shake128.Update(a);
            shake128.Update(b);
            return shake128;
        }
    }
}
