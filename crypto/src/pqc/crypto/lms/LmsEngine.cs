using System;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    internal static class LmsEngine
    {
        /// <summary>
        /// Derive the identifier and master seed of the tree below one-time key q of an LMS tree (the child of leaf q
        /// in an HSS hierarchy).
        /// </summary>
        /// <returns>
        /// { I of the child tree (16 bytes), master seed of the child tree (n bytes) }.
        /// </returns>
#if NETCOREAPP2_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        internal static ValueTuple<byte[], byte[]> DeriveChildKey(LMOtsParameters otsParameters, byte[] I,
            byte[] masterSecret, int q)
#else
        internal static Tuple<byte[], byte[]> DeriveChildKey(LMOtsParameters otsParameters, byte[] I,
            byte[] masterSecret, int q)
#endif
        {
            SeedDerive derive = new SeedDerive(I, masterSecret, LmsUtilities.GetDigest(otsParameters))
            {
                Q = q,
                J = ~1,
            };

            int n = otsParameters.N;
            byte[] childSeed = new byte[n];
            derive.DeriveSeed(true, childSeed, 0);
            byte[] postImage = new byte[n];
            derive.DeriveSeed(false, postImage, 0);
            byte[] childI = new byte[16];
            Array.Copy(postImage, 0, childI, 0, childI.Length);

#if NETCOREAPP2_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD2_0_OR_GREATER
            return new ValueTuple<byte[], byte[]>(childI, childSeed);
#else
            return new Tuple<byte[], byte[]>(childI, childSeed);
#endif
        }
    }
}
