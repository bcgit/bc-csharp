using System;
using System.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    internal static class LmsEngine
    {
        /// <summary>
        /// Take Q, the message hash, from a context that the message has been absorbed into, in the buffer shape the
        /// LM-OTS chaining expects: the N bytes of Q, followed by room for the two bytes of
        /// <see cref="LMOts.Cksm(byte[], int, LMOtsParameters)"/> that the caller appends (RFC 8554 sec. 4.5). The
        /// context cannot be used afterwards.
        /// </summary>
        internal static byte[] CollectQ(LmsContext context, LMOtsParameters otsParameters)
        {
            byte[] Q = new byte[otsParameters.N + 2];
            context.OutputQ(Q, 0);
            return Q;
        }

        //
        // Signing.
        //

        /// <summary>
        /// The context a message is absorbed into before signing with one-time key q of an LMS tree (RFC 8554 sec.
        /// 5.4.1): the randomiser C is derived and the I || q || D_MESG || C prefix is already absorbed. Consumed by
        /// <see cref="GenerateSign(LmsContext)"/>.
        /// </summary>
        internal static LmsContext GenerateSignContext(LMSigParameters sigParameters, LMOtsParameters otsParameters,
            byte[] I, int q, byte[] masterSecret, byte[][] path)
        {
            return new LMOtsPrivateKey(otsParameters, I, q, masterSecret).GetSignatureContext(sigParameters, path);
        }

        /// <summary>
        /// Attach the signed public key chain of an HSS signature (RFC 8554 sec. 6.1) to the context for its leaf tree,
        /// so that <see cref="GenerateHssSignature(int, LmsContext)"/> can emit it.
        /// </summary>
        /// <param name="context">
        /// The context to attach signed public keys to.
        /// </param>
        /// <param name="signedPubKeys">
        /// The L - 1 chaining signatures, signatures[i] made by tree i over the public key of tree i + 1, with the
        /// corresponding public key of tree i + 1.
        /// </param>
        internal static LmsContext WithSignedPublicKeys(LmsContext context, LmsSignedPubKey[] signedPubKeys) =>
            context.WithSignedPublicKeys(signedPubKeys);

        /// <summary>
        /// Complete an LMS signature over the message absorbed into a context from
        /// <see cref="GenerateSignContext(LMSigParameters, LMOtsParameters, byte[], int, byte[], byte[][])"/>.
        /// </summary>
        internal static LmsSignature GenerateSign(LmsContext context)
        {
            LMOtsPrivateKey privateKey = context.PrivateKey;

            byte[] Q = CollectQ(context, privateKey.Parameters);

            LMOtsSignature ots_signature = LMOts.LMOtsGenerateSignature(privateKey, Q, context.C);

            return new LmsSignature(privateKey.Q, ots_signature, context.SigParams, context.Path);
        }

        /// <summary>
        /// Complete and encode an HSS signature over the message absorbed into a context from
        /// <see cref="GenerateSignContext(LMSigParameters, LMOtsParameters, byte[], int, byte[], byte[][])"/> that has
        /// had its chain attached with
        /// <see cref="WithSignedPublicKeys(LmsContext, LmsSignedPubKey[])"/>.
        /// </summary>
        /// <param name="level">The number of levels in the HSS key.</param>
        /// <param name="context">The context with the message and chain.</param>
        internal static byte[] GenerateHssSignature(int level, LmsContext context)
        {
            try
            {
                return Hss.GenerateSignature(level, context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unable to encode signature", e);
            }
        }

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
