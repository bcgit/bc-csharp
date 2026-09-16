using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    internal static class LmsEngine
    {
        // Signed, since that is what U16Str takes; the value written is the RFC 8554 typecode either way.
        // TODO[lms] Private, once the tree building in LmsPrivateKeyParameters (CalcT, HashInterior) moves here
        // as bc-java's computeLeaf and computeNode.
        internal const short D_LEAF = unchecked((short)0x8282);
        internal const short D_INTR = unchecked((short)0x8383);

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
        /// An LMS private key positioned at one-time key <paramref name="q"/> of the tree named by
        /// <paramref name="I"/> (RFC 8554 sec. 5.2, Algorithm 5).
        /// </summary>
        /// <remarks>
        /// SP 800-208 sec. 4 wants one hash function across the tree and its LM-OTS keys, which the key
        /// generation parameters check; a direct call here does not pass through them. The seed length is
        /// checked by the constructor.
        /// </remarks>
        internal static LmsPrivateKeyParameters GenerateKey(LmsParameters lmsParameters, int q, byte[] I,
            byte[] masterSecret)
        {
            return new LmsPrivateKeyParameters(lmsParameters, q, I, 1 << lmsParameters.LMSigParameters.H,
                masterSecret);
        }

        /// <summary>An HSS private key at index zero, over the parameter sets <paramref name="parameters"/> names
        /// for each level (RFC 8554 sec. 6.1).</summary>
        internal static HssPrivateKeyParameters GenerateHssKeyPair(HssKeyGenerationParameters parameters)
        {
            //
            // LmsPrivateKey can derive and hold the public key so we just use an array of those.
            //
            LmsPrivateKeyParameters[] keys = new LmsPrivateKeyParameters[parameters.Depth];
            LmsSignature[] sig = new LmsSignature[parameters.Depth - 1];

            var rootLms = parameters.GetLmsParameters(0);

            byte[] masterSecret = SecureRandom.GetNextBytes(parameters.Random, rootLms.LMSigParameters.M);
            byte[] I = SecureRandom.GetNextBytes(parameters.Random, 16);

            //
            // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
            // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
            // index of zero. Rather than repeat the same reset-to-index logic in this static method.
            //

            keys[0] = GenerateKey(rootLms, 0, I, masterSecret);

            long hssKeyMaxIndex = 1L << rootLms.LMSigParameters.H;

            for (int t = 1; t < keys.Length; t++)
            {
                var lms = parameters.GetLmsParameters(t);

                keys[t] = new LmsPrivateKeyParameters(lms, 1 << lms.LMSigParameters.H);

                hssKeyMaxIndex <<= lms.LMSigParameters.H;
            }

            // if this has happened we're trying to generate a really large key
            // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
            if (hssKeyMaxIndex == 0)
            {
                hssKeyMaxIndex = long.MaxValue;
            }

            return new HssPrivateKeyParameters(parameters.Depth, keys, sig, 0, hssKeyMaxIndex);
        }

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
        internal static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature S,
            LmsPublicKeyParameters signedPublicKey)
        {
            LmsContext context = publicKey.GenerateOtsContext(S);

            signedPublicKey.UpdateDigest(context);

            return VerifySignature(publicKey, context);
        }

        /// <summary>Verify a signature over <paramref name="message"/> in one step.</summary>
        internal static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature S, byte[] message)
        {
            LmsContext context = publicKey.GenerateOtsContext(S);

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
            LmsSignature signature = (LmsSignature)context.Signature;
            LMSigParameters sigParameters = signature.SigParameters;
            byte[][] path = signature.Y;

            // Kc, the LM-OTS public key the signature computes for itself
            byte[] Kc = LMOts.LMOtsValidateSignatureCalculate(context);

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

                // The node's parity decides which side its sibling from the path goes on - left for an odd node,
                // right for an even one - while the hash itself is over the parent (RFC 8554 sec. 5.4.2 step 3).
                bool isOdd = (nodeNum & 1) == 1;
                nodeNum >>= 1;

                byte[] siblingHash = path[i++];

                digest.BlockUpdate(I, 0, I.Length);
                LmsUtilities.U32Str(nodeNum, digest);
                LmsUtilities.U16Str(D_INTR, digest);

                if (isOdd)
                {
                    digest.BlockUpdate(siblingHash, 0, siblingHash.Length);
                    digest.BlockUpdate(nodeHash, 0, nodeHash.Length);
                }
                else
                {
                    digest.BlockUpdate(nodeHash, 0, nodeHash.Length);
                    digest.BlockUpdate(siblingHash, 0, siblingHash.Length);
                }

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
