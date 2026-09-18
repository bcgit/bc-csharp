using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    internal static class LmsEngine
    {
        // Signed, since that is what U16Str takes; the value written is the RFC 8554 typecode either way.
        private const short D_LEAF = unchecked((short)0x8282);
        private const short D_INTR = unchecked((short)0x8383);

        /// <summary>
        /// Leaf node r of the tree: H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[q]), the one-time public
        /// key of leaf <paramref name="q"/> being derived from the master secret (RFC 8554 sec. 5.3, Algorithm 7).
        /// </summary>
        /// <param name="digest">The tree digest, from <see cref="LmsUtilities.GetDigest(LMSigParameters)"/>; reset
        /// on return, so one digest serves a whole walk.</param>
        /// <param name="otsParameters">The LM-OTS parameter set of the tree.</param>
        /// <param name="I">The tree identifier.</param>
        /// <param name="r">The node number of the leaf, 2^h + <paramref name="q"/>.</param>
        /// <param name="q">The one-time key the leaf holds.</param>
        /// <param name="masterSecret">The seed the tree's one-time keys are derived from.</param>
        internal static byte[] ComputeLeaf(IDigest digest, LMOtsParameters otsParameters, byte[] I, int r, int q,
            byte[] masterSecret)
        {
            return ComputeLeaf(digest, new byte[otsParameters.N], otsParameters, I, r, q, masterSecret);
        }

        /// <summary>
        /// <see cref="ComputeLeaf(IDigest, LMOtsParameters, byte[], int, int, byte[])"/> with the one-time public
        /// key hash derived into a caller's buffer, so a walk over many leaves reuses one.
        /// </summary>
        /// <param name="digest">The tree digest, from <see cref="LmsUtilities.GetDigest(LMSigParameters)"/>; reset
        /// on return, so one digest serves a whole walk.</param>
        /// <param name="K">Scratch for the one-time public key hash, at least n bytes; overwritten.</param>
        /// <param name="otsParameters">The LM-OTS parameter set of the tree.</param>
        /// <param name="I">The tree identifier.</param>
        /// <param name="r">The node number of the leaf, 2^h + <paramref name="q"/>.</param>
        /// <param name="q">The one-time key the leaf holds.</param>
        /// <param name="masterSecret">The seed the tree's one-time keys are derived from.</param>
        internal static byte[] ComputeLeaf(IDigest digest, byte[] K, LMOtsParameters otsParameters, byte[] I, int r,
            int q, byte[] masterSecret)
        {
            LMOts.LmsOtsGeneratePublicKey(otsParameters, I, q, masterSecret, K);

            LmsUtilities.ByteArray(I, digest);
            LmsUtilities.U32Str(r, digest);
            LmsUtilities.U16Str(D_LEAF, digest);
            digest.BlockUpdate(K, 0, otsParameters.N);

            byte[] T = new byte[digest.GetDigestSize()];
            digest.DoFinal(T, 0);
            return T;
        }

        /// <summary>
        /// Interior node r of the tree: H(I || u32str(r) || u16str(D_INTR) || T[2r] || T[2r+1])
        /// (RFC 8554 sec. 5.3, Algorithm 7).
        /// </summary>
        /// <param name="digest">The tree digest, from <see cref="LmsUtilities.GetDigest(LMSigParameters)"/>; reset
        /// on return, so one digest serves a whole walk.</param>
        /// <param name="I">The tree identifier.</param>
        /// <param name="r">The node number of the node computed, half that of its children.</param>
        /// <param name="left">The node at 2r.</param>
        /// <param name="right">The node at 2r + 1.</param>
        internal static byte[] ComputeNode(IDigest digest, byte[] I, int r, byte[] left, byte[] right)
        {
            LmsUtilities.ByteArray(I, digest);
            LmsUtilities.U32Str(r, digest);
            LmsUtilities.U16Str(D_INTR, digest);
            LmsUtilities.ByteArray(left, digest);
            LmsUtilities.ByteArray(right, digest);

            byte[] T = new byte[digest.GetDigestSize()];
            digest.DoFinal(T, 0);
            return T;
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
        /// Sign a message in one step with the current one-time key of <paramref name="privateKey"/>.
        /// </summary>
        /// <remarks>
        /// For tests. The library signs through <see cref="LmsPrivateKeyParameters.GenerateLmsContext"/> so that
        /// the message can be absorbed as it arrives, and bc-java dropped the one-step form at promotion.
        /// </remarks>
        internal static LmsSignature GenerateSign(LmsPrivateKeyParameters privateKey, byte[] message)
        {
            LmsContext context = privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            return GenerateSign(context);
        }

        /// <summary>
        /// Complete an LMS signature over the message absorbed into a context from
        /// <see cref="GenerateSignContext(LMSigParameters, LMOtsParameters, byte[], int, byte[], byte[][])"/>.
        /// </summary>
        internal static LmsSignature GenerateSign(LmsContext context) => context.GenerateSignature();

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
                return CreateHssSignature(level, context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unable to encode signature", e);
            }
        }

        /// <summary>
        /// Sign a message in one step with the current one-time key of <paramref name="privateKey"/>, which the
        /// signature advances past.
        /// </summary>
        /// <remarks>
        /// For tests, as <see cref="GenerateSign(LmsPrivateKeyParameters, byte[])"/> is.
        /// </remarks>
        internal static HssSignature GenerateHssSignature(HssPrivateKeyParameters privateKey, byte[] message)
        {
            // The key claims its own index and the bottom key's one-time index under the one monitor; claiming
            // here as well would reopen the window between the two.
            LmsContext context = privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            return CreateHssSignature(privateKey.Level, context);
        }

        private static HssSignature CreateHssSignature(int level, LmsContext context) =>
            new HssSignature(level - 1, context.SignedPubKeys, GenerateSign(context));

        /// <summary>
        /// Verify a signature over a message in one step, the counterpart of
        /// <see cref="GenerateHssSignature(HssPrivateKeyParameters, byte[])"/> and here for the same reason.
        /// </summary>
        internal static bool VerifyHssSignature(HssPublicKeyParameters publicKey, HssSignature signature,
            byte[] message)
        {
            LmsContext context = publicKey.GenerateLmsContext(signature);

            context.BlockUpdate(message, 0, message.Length);

            return VerifyHssSignature(publicKey, context);
        }

        /// <summary>
        /// Verify the HSS signature a context carries over the message absorbed into it (RFC 8554 sec. 6.3): each
        /// chaining signature over the next tree's public key, then the leaf tree's signature over the message.
        /// </summary>
        /// <remarks>
        /// Every level is verified even once one has failed, so the work done does not say which level a bad
        /// signature failed at.
        /// </remarks>
        internal static bool VerifyHssSignature(HssPublicKeyParameters publicKey, LmsContext context)
        {
            LmsSignedPubKey[] signedPubKeys = context.SignedPubKeys;

            if (signedPubKeys.Length != publicKey.Level - 1)
                return false;

            LmsPublicKeyParameters key = publicKey.LmsPublicKey;
            bool passed = true;

            for (int i = 0; i < signedPubKeys.Length; i++)
            {
                LmsPublicKeyParameters nextKey = signedPubKeys[i].PublicKey;

                passed &= VerifySignature(key, signedPubKeys[i].Signature, nextKey);

                key = nextKey;
            }

            return passed & key.Verify(context);
        }

        /// <summary>Verify a signature over the encoding of <paramref name="signedPublicKey"/>, the chaining
        /// signature an HSS hierarchy makes when one tree signs the public key of the tree below it.</summary>
        internal static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature signature,
            LmsPublicKeyParameters signedPublicKey)
        {
            LmsContext context = publicKey.GenerateOtsContext(signature);

            signedPublicKey.UpdateDigest(context);

            return VerifySignature(publicKey, context);
        }

        /// <summary>Verify a signature over <paramref name="message"/> in one step.</summary>
        internal static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature signature, byte[] message)
        {
            LmsContext context = publicKey.GenerateOtsContext(signature);

            LmsUtilities.ByteArray(message, context);

            return VerifySignature(publicKey, context);
        }

        /// <summary>
        /// Verify the LMS signature a context carries over the message absorbed into it: rebuild the Merkle path
        /// from the one-time public key the signature computes for itself, up to the root the key commits to
        /// (RFC 8554 sec. 5.4.2).
        /// </summary>
        internal static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsContext context)
        {
            // Guaranteed by every route the library has to a verification context, all of which reach
            // LMOtsPublicKey.CreateOtsContext with a decoded LMS signature. What is left is a context built by
            // hand through the public constructor, which takes the signature as an object.
            LmsSignature signature = context.Signature as LmsSignature
                ?? throw new InvalidOperationException("context was not created from an LMS signature");
            LMSigParameters sigParameters = signature.SigParameters;
            byte[][] path = signature.Y;

            // Kc, the LM-OTS public key the signature computes for itself
            byte[] Kc = context.CalculateKc();

            byte[] I = publicKey.InternalI;
            IDigest digest = LmsUtilities.GetDigest(sigParameters);

            // The node the walk is at, and the hash it has computed for it: the leaf of the one-time key that
            // signed, then each parent in turn, leaving the root the signature claims.
            // RFC 8554 sec. 5.4.2 step 4: node_num = 2^h + q, tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
            int nodeNum = (1 << sigParameters.H) + signature.Q;
            byte[] nodeHash = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(I, 0, I.Length);
            LmsUtilities.U32Str(nodeNum, digest);
            LmsUtilities.U16Str(D_LEAF, digest);
            digest.BlockUpdate(Kc, 0, Kc.Length);
            digest.DoFinal(nodeHash, 0);

            int i = 0;

            while (nodeNum > 1)
            {
                // The path and the node count can get out of sync with an invalid signature, so fail gracefully
                // rather than index past the path the signature carries.
                if (i >= path.Length)
                    return false;

                byte[] siblingHash = path[i++];

                // The node's parity decides which side its sibling from the path goes on - left for an odd node,
                // right for an even one - while the hash itself is over the parent (RFC 8554 sec. 5.4.2 step 4).
                bool isOdd = (nodeNum & 1) == 1;
                nodeNum >>= 1;

                byte[] left = isOdd ? siblingHash : nodeHash;
                byte[] right = isOdd ? nodeHash : siblingHash;

                digest.BlockUpdate(I, 0, I.Length);
                LmsUtilities.U32Str(nodeNum, digest);
                LmsUtilities.U16Str(D_INTR, digest);
                digest.BlockUpdate(left, 0, left.Length);
                digest.BlockUpdate(right, 0, right.Length);
                digest.DoFinal(nodeHash, 0);
            }

            return publicKey.MatchesT1(nodeHash);
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
