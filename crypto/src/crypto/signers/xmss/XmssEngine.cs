using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// The XMSS and XMSS^MT (RFC 8391) operations the key parameter classes, the key pair generators and the signers
    /// are built on: key pair generation, signature generation and verification, the WOTS+ and OID parameter
    /// derivations, and the handful of traversal state and encoding helpers the key classes need.
    /// </summary>
    /// <remarks>
    /// bc-java's <c>XMSSEngine</c> is public because its key parameter classes live in another package; here they
    /// are in the same assembly, so this, like the traversal state types, is internal.
    /// </remarks>
    internal static class XmssEngine
    {
        /// <summary>A tree digest by its OID.</summary>
        internal static IDigest GetDigest(DerObjectIdentifier oid) => XmssDigestUtilities.GetDigest(oid);

        /// <summary>
        /// The number of n-byte elements in a WOTS+ key or signature, len = len1 + len2 (RFC 8391 sec. 3.1.1).
        /// Rejects a tree digest and security parameter that are not a registered WOTS+ combination.
        /// </summary>
        internal static int GetWotsPlusLen(DerObjectIdentifier treeDigestOid, int digestSize) =>
            new WotsPlusParameters(treeDigestOid, digestSize).Len;

        /// <summary>
        /// The RFC 8391 sec. 5.4 XMSS^MT parameter-set identifier for this combination, or 0 when the combination is
        /// not one of the registered sets.
        /// </summary>
        internal static int LookupXmssMTOid(string treeDigest, int digestSize, int winternitzParameter, int len,
            int height, int layers)
        {
            DefaultXmssMTOid oid = DefaultXmssMTOid.Lookup(treeDigest, digestSize, winternitzParameter, len, height,
                layers);

            return (oid != null) ? oid.Oid : 0;
        }

        /// <summary>Generate an XMSS key pair (RFC 8391 sec. 4.1.7).</summary>
        internal static AsymmetricCipherKeyPair GenerateKeyPair(XmssParameters parameters, SecureRandom prng)
        {
            int n = parameters.TreeDigestSize;
            byte[] secretKeySeed = SecureRandom.GetNextBytes(prng, n);
            byte[] secretKeyPrf = SecureRandom.GetNextBytes(prng, n);
            byte[] publicSeed = SecureRandom.GetNextBytes(prng, n);

            Bds bdsState = new Bds(parameters, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0));
            byte[] root = bdsState.Root.GetValue();

            XmssPrivateKeyParameters.Builder privateKeyBuilder = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(secretKeySeed).WithSecretKeyPrf(secretKeyPrf)
                .WithPublicSeed(publicSeed).WithRoot(root)
                .WithOwnedBdsState(bdsState);
            XmssPrivateKeyParameters privateKey;
            try
            {
                privateKey = privateKeyBuilder.Build();
            }
            finally
            {
                // a Build() that throws has still been handed the secrets
                privateKeyBuilder.ClearSecrets();
            }

            XmssPublicKeyParameters publicKey = new XmssPublicKeyParameters.Builder(parameters).WithRoot(root)
                .WithPublicSeed(publicSeed).Build();

            // the key holds copies of its own, and its builder's have been wiped. The state, adopted by the key,
            // retains the WOTS+ secret key of the last leaf it walked; a state imports a fresh one before each leaf it
            // computes, so it can go
            Arrays.ZeroMemory(secretKeySeed);
            Arrays.ZeroMemory(secretKeyPrf);
            bdsState.ClearSecrets();

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        /// <summary>Generate an XMSS^MT key pair (RFC 8391 sec. 4.2.5).</summary>
        /// <remarks>
        /// Only the top layer's state is built here, since its root is the public root; every layer below is built
        /// lazily, by the first signature that needs it.
        /// </remarks>
        internal static AsymmetricCipherKeyPair GenerateMTKeyPair(XmssMTParameters parameters, SecureRandom prng)
        {
            XmssParameters xmssParams = parameters.XmssParameters;

            int n = parameters.TreeDigestSize;
            byte[] secretKeySeed = SecureRandom.GetNextBytes(prng, n);
            byte[] secretKeyPrf = SecureRandom.GetNextBytes(prng, n);
            byte[] publicSeed = SecureRandom.GetNextBytes(prng, n);

            BdsStateMap bdsState = new BdsStateMap((1L << parameters.Height) - 1);

            /* get root */
            int rootLayerIndex = parameters.Layers - 1;
            byte[] otsAddress = XmssAddress.OtsHashAddress(rootLayerIndex, 0L, 0);

            /* store BDS instance of root xmss instance */
            Bds bdsRoot = new Bds(xmssParams, publicSeed, secretKeySeed, otsAddress);
            byte[] root = bdsRoot.Root.GetValue();
            bdsState.Put(rootLayerIndex, bdsRoot);

            /* set XMSS^MT root / create public key */
            XmssMTPrivateKeyParameters.Builder privateKeyBuilder = new XmssMTPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(secretKeySeed).WithSecretKeyPrf(secretKeyPrf).WithPublicSeed(publicSeed)
                .WithRoot(root).WithOwnedBdsState(bdsState);
            XmssMTPrivateKeyParameters privateKey;
            try
            {
                privateKey = privateKeyBuilder.Build();
            }
            finally
            {
                // a Build() that throws has still been handed the secrets
                privateKeyBuilder.ClearSecrets();
            }
            XmssMTPublicKeyParameters publicKey = new XmssMTPublicKeyParameters.Builder(parameters).WithRoot(root)
                .WithPublicSeed(publicSeed).Build();

            // the key holds copies of its own, and its builder's have been wiped. The state map, adopted by the key,
            // has a root layer state that retains the WOTS+ secret key of the last leaf it walked; a state imports a
            // fresh one before each leaf it computes, so it can go
            Arrays.ZeroMemory(secretKeySeed);
            Arrays.ZeroMemory(secretKeyPrf);
            bdsState.ClearSecrets();

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Whether the key's BDS traversal state has been initialised, i.e. whether it can sign. A key decoded from
        /// an encoding that carried no traversal state has none.
        /// </summary>
        internal static bool HasTraversalState(XmssPrivateKeyParameters privateKey) =>
            !privateKey.GetBdsState().IsAuthenticationPathEmpty;

        /// <summary>
        /// Whether the key's BDS traversal state map has been initialised, i.e. whether it can sign: a map with no
        /// layers in it has nothing to sign from.
        /// </summary>
        internal static bool HasTraversalState(XmssMTPrivateKeyParameters privateKey) =>
            !privateKey.GetBdsState().IsEmpty;

        /// <summary>
        /// Generate an XMSS signature over <paramref name="message"/> and advance the key's traversal state
        /// (RFC 8391 sec. 4.1.9).
        /// </summary>
        /// <remarks>
        /// The key is held locked across the whole check, sign and advance sequence. RFC 8391 sec. 1.1 requires each
        /// one-time key to be used exactly once, and this both reads the index and rolls the key past it: two
        /// threads entering with the same key and nothing serializing them would sign different messages under the
        /// same one-time key. The lock is the key's own, which its methods take too; .NET monitors are reentrant.
        /// </remarks>
        internal static byte[] GenerateSignature(XmssPrivateKeyParameters privateKey, byte[] message)
        {
            lock (privateKey)
            {
                return DoGenerateSignature(privateKey, message);
            }
        }

        private static byte[] DoGenerateSignature(XmssPrivateKeyParameters privateKey, byte[] message)
        {
            XmssParameters parameters = privateKey.Parameters;
            WotsPlus wotsPlus = NewWotsPlus(parameters);
            KeyedHashFunctions khf = wotsPlus.Khf;

            if (privateKey.GetUsagesRemaining() <= 0)
                throw new ExhaustedPrivateKeyException("no usages of private key remaining");
            if (!HasTraversalState(privateKey))
                throw new InvalidOperationException("not initialized");
            //
            // a state that has signed is replaced by the RollKey() beside the MarkUsed() below, so a key still holding
            // a marked one did not come from this engine - it was restored from an encoding written that way, which
            // puts the key back on an index it has already used. RFC 8391 sec. 1.1 makes signing there a private key
            // compromise, so it is refused here. Ahead of the try, as the two checks above are: a refused signature
            // must not reach the finally that rolls the key.
            //
            if (privateKey.GetBdsState().IsUsed)
            {
                throw new InvalidOperationException(
                    "one time key at index " + privateKey.Index + " has already signed");
            }
            //
            // and here for the same reason. The secret material the try reads is zeroized, so the signature would
            // fail part way through it and reach the finally, where MarkUsed() would mark a state no signature used
            // and RollKey() would refuse the destroyed key in its turn - replacing the exception the try raised.
            //
            if (privateKey.IsDestroyed)
                throw new InvalidOperationException("key destroyed");

            byte[] secretKeyPrf = null, secretKeySeed = null;
            try
            {
                int index = privateKey.Index;

                /* create (randomized keyed) messageDigest of message */
                secretKeyPrf = privateKey.GetSecretKeyPrf();
                byte[] random = khf.Prf(secretKeyPrf, XmssUtilities.ToBytesBigEndian(index, 32));
                byte[] concatenated = HMsgKey(random, privateKey.GetRoot(), index, parameters.TreeDigestSize);
                byte[] messageDigest = khf.HMsg(concatenated, message);

                /* create signature for messageDigest */
                byte[] otsAddress = XmssAddress.OtsHashAddress(0, 0L, index);
                secretKeySeed = privateKey.GetSecretKeySeed();
                byte[][] wotsPlusSignature = WotsSign(wotsPlus, secretKeySeed, privateKey.GetPublicSeed(),
                    messageDigest, otsAddress);

                // every call in the chain is XmssSignature.Builder's own, so Build() is too
                return new XmssSignature.Builder(parameters).WithIndex(index).WithRandom(random)
                    .WithWotsPlusSignature(wotsPlusSignature)
                    .WithAuthPath(privateKey.GetBdsState().GetAuthenticationPath())
                    .Build().ToByteArray();
            }
            finally
            {
                if (secretKeyPrf != null)
                {
                    Arrays.ZeroMemory(secretKeyPrf);
                }
                if (secretKeySeed != null)
                {
                    Arrays.ZeroMemory(secretKeySeed);
                }
                wotsPlus.ClearSecretKeySeed();

                privateKey.GetBdsState().MarkUsed();
                privateKey.RollKey();
            }
        }

        /// <summary>Verify an XMSS signature (RFC 8391 sec. 4.1.10).</summary>
        /// <remarks>
        /// A signature that will not decode at all is reported as a failed verification rather than raised. An absent
        /// one is not the same thing: there are no bytes to decode, so a null signature is the caller's mistake and
        /// is raised.
        /// </remarks>
        internal static bool VerifySignature(XmssPublicKeyParameters publicKey, byte[] message, byte[] signature)
        {
            // ahead of the decode below, whose catch would otherwise fold a missing argument into the same false a
            // malformed one gets
            if (signature == null)
                throw new ArgumentNullException(nameof(signature), "signature == null");

            XmssParameters parameters = publicKey.Parameters;
            WotsPlus wotsPlus = NewWotsPlus(parameters);
            KeyedHashFunctions khf = wotsPlus.Khf;

            XmssSignature sig;
            try
            {
                sig = new XmssSignature.Builder(parameters).WithSignature(signature).Build();
            }
            catch (Exception)
            {
                // malformed/truncated signature: ArgumentException (wrong length, index outside the tree) or
                // InvalidOperationException (negative index) is a signature that does not verify
                return false;
            }

            int index = sig.Index;

            /* reinitialize WOTS+ object */
            wotsPlus.ImportKeys(new byte[parameters.TreeDigestSize], publicKey.GetPublicSeed());

            // read once: as the middle of the H_msg key, and as what the root climbed out of the signature is
            // compared against
            byte[] root = publicKey.GetRoot();

            /* create message digest */
            byte[] concatenated = HMsgKey(sig.GetRandom(), root, index, parameters.TreeDigestSize);
            byte[] messageDigest = khf.HMsg(concatenated, message);

            int xmssHeight = parameters.Height;
            int indexLeaf = XmssUtilities.GetLeafIndex(index, xmssHeight);

            /* get root from signature */
            byte[] otsAddress = XmssAddress.OtsHashAddress(0, 0L, index);
            XmssNode rootNodeFromSignature = XmssVerifierUtilities.GetRootNodeFromSignature(wotsPlus, xmssHeight,
                messageDigest, sig, otsAddress, indexLeaf);

            return Arrays.FixedTimeEquals(rootNodeFromSignature.GetValue(), root);
        }

        /// <summary>
        /// Generate an XMSS^MT signature over <paramref name="message"/> and advance the key's traversal state
        /// (RFC 8391 sec. 4.2.7). The key is held locked for the whole sequence, for the reason given on
        /// <see cref="GenerateSignature"/>.
        /// </summary>
        internal static byte[] GenerateMTSignature(XmssMTPrivateKeyParameters privateKey, byte[] message)
        {
            lock (privateKey)
            {
                return DoGenerateMTSignature(privateKey, message);
            }
        }

        private static byte[] DoGenerateMTSignature(XmssMTPrivateKeyParameters privateKey, byte[] message)
        {
            XmssMTParameters parameters = privateKey.Parameters;
            XmssParameters xmssParams = parameters.XmssParameters;
            WotsPlus wotsPlus = NewWotsPlus(parameters);

            if (privateKey.GetUsagesRemaining() <= 0)
                throw new ExhaustedPrivateKeyException("no usages of private key remaining");
            if (!HasTraversalState(privateKey))
                throw new InvalidOperationException("not initialized");
            //
            // as the XMSS path, on the layer zero state - the one whose leaf signs the message, and so the one a
            // second signature must never reuse. The one allowance: on the first leaf of a subtree the signer builds
            // layer zero fresh, so the marked state carried over from the end of the previous subtree, at its last
            // leaf, is legitimate there and is about to be thrown away - provided it is the state of the subtree just
            // before, which the index check below confirms. A marked state at leaf 0 is not that one: it is the state
            // the signature at leaf 0 spent, left by a roll that did not complete, and bc-java's check, which skips
            // every leaf 0 position, would sign leaf 0 again from it.
            //
            Bds layerZero = privateKey.GetBdsState().Get(0);
            if (layerZero != null && layerZero.IsUsed
                && !(XmssUtilities.GetLeafIndex(privateKey.Index, xmssParams.Height) == 0
                    && layerZero.Index == (1 << xmssParams.Height) - 1))
            {
                throw new InvalidOperationException(
                    "one time key at index " + privateKey.Index + " has already signed");
            }
            //
            // and here for the reason the single tree gives: the secret material the descent below reads is
            // zeroized, so the signature would fail part way through it and reach the finally, where MarkUsed() would
            // mark a state no signature used and RollKey() would replace the exception with its own. Ahead of the
            // index check too, which reads the secret seed.
            //
            if (privateKey.IsDestroyed)
                throw new InvalidOperationException("key destroyed");
            //
            // and the other half of the same question: whether the layer zero state is standing where the key says
            // it is. XMSS^MT records its position twice - the index field, and the per-layer states - so a key can be
            // holding two answers, and a signature made from one that does would consume a one-time key and not
            // verify (bc-java github #2414), or would sign again at an index already used. Ahead of the try below,
            // as the checks above are: a refused signature must not reach the roll.
            //
            privateKey.ValidateIndex();

            //
            // the map's own lock, held for the whole descent below and the roll that follows it: the layer states
            // built below are installed into the live map, and a caller copying that map does not hold the key's
            // lock. Lock order is always key then map; a state map holds no reference to a key.
            //
            BdsStateMap bdsState = privateKey.GetBdsState();

            lock (bdsState)
            {
                byte[] secretKeyPrf = null, secretKeySeed = null;
                try
                {
                    byte[] publicSeed = privateKey.GetPublicSeed();
                    secretKeySeed = privateKey.GetSecretKeySeed();

                    long globalIndex = privateKey.Index;
                    int xmssHeight = xmssParams.Height;

                    /* compress message */
                    secretKeyPrf = privateKey.GetSecretKeyPrf();
                    byte[] random = wotsPlus.Khf.Prf(secretKeyPrf, XmssUtilities.ToBytesBigEndian(globalIndex, 32));
                    byte[] concatenated = HMsgKey(random, privateKey.GetRoot(), globalIndex,
                        parameters.TreeDigestSize);
                    byte[] messageDigest = wotsPlus.Khf.HMsg(concatenated, message);

                    XmssMTSignature signature = new XmssMTSignature.Builder(parameters).WithIndex(globalIndex)
                        .WithRandom(random).Build();

                    /* layer 0 */
                    long indexTree = XmssUtilities.GetTreeIndex(globalIndex, xmssHeight);
                    int indexLeaf = XmssUtilities.GetLeafIndex(globalIndex, xmssHeight);

                    /* reset xmss */
                    wotsPlus.ImportKeys(new byte[parameters.TreeDigestSize], publicSeed);

                    /* create signature with XMSS tree on layer 0 */

                    /* adjust addresses */
                    byte[] otsAddress = XmssAddress.OtsHashAddress(0, indexTree, indexLeaf);

                    /* get authentication path from BDS */
                    if (bdsState.Get(0) == null || indexLeaf == 0)
                    {
                        bdsState.Put(0, new Bds(xmssParams, publicSeed, secretKeySeed, otsAddress));
                    }

                    /* sign message digest */
                    byte[][] wotsPlusSignature = WotsSign(wotsPlus, secretKeySeed, publicSeed, messageDigest,
                        otsAddress);

                    XmssReducedSignature reducedSignature = new XmssReducedSignature.Builder(xmssParams)
                        .WithWotsPlusSignature(wotsPlusSignature)
                        .WithAuthPath(bdsState.Get(0).GetAuthenticationPath())
                        .Build();

                    signature.ReducedSignatures.Add(reducedSignature);

                    /* loop over remaining layers */
                    for (int layer = 1; layer < parameters.Layers; layer++)
                    {
                        /* get root of layer - 1 */
                        XmssNode root = bdsState.Get(layer - 1).Root;

                        indexLeaf = XmssUtilities.GetLeafIndex(indexTree, xmssHeight);
                        indexTree = XmssUtilities.GetTreeIndex(indexTree, xmssHeight);

                        /* adjust addresses */
                        otsAddress = XmssAddress.OtsHashAddress(layer, indexTree, indexLeaf);

                        /* sign root digest of layer - 1 */
                        wotsPlusSignature = WotsSign(wotsPlus, secretKeySeed, publicSeed, root.GetValue(), otsAddress);

                        /* get authentication path from BDS */
                        if (bdsState.Get(layer) == null
                            || XmssUtilities.IsNewBdsInitNeeded(globalIndex, xmssHeight, layer))
                        {
                            bdsState.Put(layer, new Bds(xmssParams, publicSeed, secretKeySeed, otsAddress));
                        }

                        reducedSignature = new XmssReducedSignature.Builder(xmssParams)
                            .WithWotsPlusSignature(wotsPlusSignature)
                            .WithAuthPath(bdsState.Get(layer).GetAuthenticationPath())
                            .Build();

                        signature.ReducedSignatures.Add(reducedSignature);
                    }

                    return signature.ToByteArray();
                }
                finally
                {
                    if (secretKeyPrf != null)
                    {
                        Arrays.ZeroMemory(secretKeyPrf);
                    }
                    if (secretKeySeed != null)
                    {
                        Arrays.ZeroMemory(secretKeySeed);
                    }
                    wotsPlus.ClearSecretKeySeed();

                    bdsState.MarkUsed();
                    privateKey.RollKey();
                }
            }
        }

        /// <summary>Verify an XMSS^MT signature (RFC 8391 sec. 4.2.8).</summary>
        /// <remarks>
        /// As with <see cref="VerifySignature"/>, a signature that will not decode is reported as a failed
        /// verification rather than raised, and an absent one is raised.
        /// </remarks>
        internal static bool VerifyMTSignature(XmssMTPublicKeyParameters publicKey, byte[] message, byte[] signature)
        {
            // ahead of the decode below, whose catch would otherwise fold a missing argument into the same false a
            // malformed one gets
            if (signature == null)
                throw new ArgumentNullException(nameof(signature), "signature == null");

            XmssMTParameters parameters = publicKey.Parameters;
            XmssParameters xmssParams = parameters.XmssParameters;
            WotsPlus wotsPlus = NewWotsPlus(parameters);

            XmssMTSignature sig;
            try
            {
                sig = new XmssMTSignature.Builder(parameters).WithSignature(signature).Build();
            }
            catch (Exception)
            {
                // malformed/truncated signature: ArgumentException (wrong length, index outside the hypertree) or
                // InvalidOperationException (negative index) is a signature that does not verify
                return false;
            }

            // read once, as in VerifySignature and for the same reason
            byte[] root = publicKey.GetRoot();

            byte[] concatenated = HMsgKey(sig.GetRandom(), root, sig.Index, parameters.TreeDigestSize);
            byte[] messageDigest = wotsPlus.Khf.HMsg(concatenated, message);

            long globalIndex = sig.Index;
            int xmssHeight = xmssParams.Height;
            long indexTree = XmssUtilities.GetTreeIndex(globalIndex, xmssHeight);
            int indexLeaf = XmssUtilities.GetLeafIndex(globalIndex, xmssHeight);

            /* adjust xmss */
            wotsPlus.ImportKeys(new byte[parameters.TreeDigestSize], publicKey.GetPublicSeed());

            /* prepare addresses */
            byte[] otsAddress = XmssAddress.OtsHashAddress(0, indexTree, indexLeaf);

            /* get root node on layer 0 */
            XmssReducedSignature xmssMTSignature = sig.ReducedSignatures[0];
            XmssNode rootNode = XmssVerifierUtilities.GetRootNodeFromSignature(wotsPlus, xmssHeight, messageDigest,
                xmssMTSignature, otsAddress, indexLeaf);
            for (int layer = 1; layer < parameters.Layers; layer++)
            {
                xmssMTSignature = sig.ReducedSignatures[layer];
                indexLeaf = XmssUtilities.GetLeafIndex(indexTree, xmssHeight);
                indexTree = XmssUtilities.GetTreeIndex(indexTree, xmssHeight);

                /* adjust address */
                otsAddress = XmssAddress.OtsHashAddress(layer, indexTree, indexLeaf);

                /* get root node */
                rootNode = XmssVerifierUtilities.GetRootNodeFromSignature(wotsPlus, xmssHeight, rootNode.GetValue(),
                    xmssMTSignature, otsAddress, indexLeaf);
            }

            /* compare roots */
            return Arrays.FixedTimeEquals(rootNode.GetValue(), root);
        }

        /// <summary>
        /// A fresh BDS traversal state for a key at <paramref name="index"/>, built at the all-zero OTS hash address
        /// an XMSS key starts from.
        /// </summary>
        /// <exception cref="ArgumentException">if <paramref name="index"/> is out of range for the parameter set.
        /// </exception>
        internal static Bds CreateBds(XmssParameters parameters, byte[] publicSeed, byte[] secretKeySeed, int index)
        {
            int height = parameters.Height;

            // the state is reached by walking the tree one authentication path at a time, so an index out of range
            // has to be refused before the walk rather than by the walk: it would otherwise cost a full tree of
            // authentication paths to arrive at the same answer.
            if (!IsStoredIndexValid(height, index))
                throw new ArgumentException("index out of bounds");

            int maxIndex = (1 << height) - 1;

            if (index > maxIndex)
            {
                // every leaf is spent. There is no traversal state to walk to, and this is the state RollKey() leaves
                // behind at the same point.
                return new Bds(parameters, maxIndex, index);
            }

            return new Bds(parameters, publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0), index);
        }

        /// <summary>
        /// A fresh BDS traversal state map for an XMSS^MT key at <paramref name="globalIndex"/>, the multi-tree
        /// counterpart of <see cref="CreateBds"/>.
        /// </summary>
        /// <remarks>
        /// The map a key at index 0 gets holds the top layer alone, as key generation's does, and the layers below
        /// stay empty until a signature needs them, so nothing downstream can tell an out-of-range index by looking at
        /// what this returns: the structural check passes over the layers a map does not have, and so does the index
        /// check. That makes the bound here the only place the index is answered.
        /// </remarks>
        /// <exception cref="ArgumentException">if <paramref name="globalIndex"/> is out of range for the parameter
        /// set.</exception>
        internal static BdsStateMap CreateBdsStateMap(XmssMTParameters parameters, byte[] publicSeed,
            byte[] secretKeySeed, long globalIndex)
        {
            int totalHeight = parameters.Height;

            if (!IsStoredIndexValid(totalHeight, globalIndex))
                throw new ArgumentException("index out of bounds");

            long maxIndex = (1L << totalHeight) - 1;

            if (globalIndex > maxIndex)
            {
                // every leaf of the hypertree is spent, and this is the state RollKey() leaves behind at the same
                // point - as on the single-tree side, where CreateBds says the same.
                return new BdsStateMap(maxIndex);
            }

            return new BdsStateMap(parameters, globalIndex, publicSeed, secretKeySeed);
        }

        /// <summary>
        /// The traversal state for the next index, i.e. with the authentication path advanced one leaf.
        /// </summary>
        internal static Bds GetNextBdsState(Bds bdsState, byte[] publicSeed, byte[] secretKeySeed) =>
            bdsState.GetNextState(publicSeed, secretKeySeed, XmssAddress.OtsHashAddress(0, 0L, 0));

        /// <summary>
        /// The XMSS^MT traversal state for the leaf after <paramref name="globalIndex"/>. The state passed in is left
        /// where it is and a new one comes back, as <see cref="GetNextBdsState"/> does for the single tree, so the
        /// key replacing its state with it moves its index and its state together or not at all.
        /// </summary>
        internal static BdsStateMap GetNextBdsStateMap(BdsStateMap bdsState, XmssMTParameters parameters,
            long globalIndex, byte[] publicSeed, byte[] secretKeySeed)
        {
            return bdsState.GetNextState(parameters, globalIndex, publicSeed, secretKeySeed);
        }

        /// <summary>
        /// The BDS traversal state as it is carried in an XMSS private key encoding, with its checksum bound to the
        /// owning key's public seed (bc-java github #2414).
        /// </summary>
        /// <exception cref="IOException">if the state is not one the codec can write.</exception>
        internal static byte[] GetEncodedBdsState(Bds bdsState, byte[] publicSeed) =>
            XmssUtilities.Serialize(bdsState, publicSeed);

        /// <summary>
        /// The BDS traversal state map as it is carried in an XMSS^MT private key encoding, with its checksum bound
        /// to the owning key's public seed (bc-java github #2414).
        /// </summary>
        /// <exception cref="IOException">if the state map is not one the codec can write.</exception>
        internal static byte[] GetEncodedBdsState(BdsStateMap bdsState, byte[] publicSeed) =>
            XmssUtilities.Serialize(bdsState, publicSeed);

        /// <summary>
        /// Zeroize the secret material a BDS traversal state retains - the WOTS+ secret key its hash-function
        /// instance imported for the last leaf it processed. The tree nodes are kept; they are not secret.
        /// </summary>
        internal static void ClearSecrets(Bds bdsState)
        {
            bdsState.ClearSecrets();
        }

        /// <summary>
        /// Zeroize the secret material retained by every layer of an XMSS^MT traversal state; see
        /// <see cref="ClearSecrets(Bds)"/>.
        /// </summary>
        internal static void ClearSecrets(BdsStateMap bdsState)
        {
            bdsState.ClearSecrets();
        }

        /// <summary>
        /// Recover an XMSS BDS traversal state from a private key encoding, checking its checksum against the owning
        /// key's public seed (bc-java github #2414).
        /// </summary>
        /// <remarks>
        /// The state comes back without a WOTS+ instance; the caller gives it one with
        /// <see cref="Bds.WithWotsDigest(DerObjectIdentifier, int)"/> before it is used.
        /// </remarks>
        /// <exception cref="IOException">if the data is not an encoding of an XMSS traversal state.</exception>
        internal static Bds GetBdsFromEncoding(byte[] encoding, byte[] publicSeed) =>
            (Bds)XmssUtilities.Deserialize(encoding, typeof(Bds), publicSeed);

        /// <summary>
        /// Recover an XMSS^MT BDS traversal state map from a private key encoding, checking its checksum against the
        /// owning key's public seed (bc-java github #2414).
        /// </summary>
        /// <remarks>
        /// The map's layers come back without WOTS+ instances; the caller gives them some with
        /// <see cref="BdsStateMap.WithMaxIndex"/> before the map is used.
        /// </remarks>
        /// <exception cref="IOException">if the data is not an encoding of an XMSS^MT traversal state map.
        /// </exception>
        internal static BdsStateMap GetBdsStateMapFromEncoding(byte[] encoding, byte[] publicSeed) =>
            (BdsStateMap)XmssUtilities.Deserialize(encoding, typeof(BdsStateMap), publicSeed);

        /// <summary>
        /// Whether <paramref name="index"/> is in range for the index field of a stored private key over a tree of
        /// this height, i.e. 0 &lt;= index &lt;= 2^height.
        /// </summary>
        /// <remarks>
        /// The bound is one leaf wider than the one an index a signature can be made at satisfies, because a key that
        /// has been used up carries the index one past its last leaf, and that is the state that most needs to
        /// survive being written out and read back. The tighter bound against the key's own maximum index is applied
        /// by <see cref="Bds.Validate()"/> once the traversal state itself has been recovered.
        /// </remarks>
        internal static bool IsStoredIndexValid(int height, long index) => index >= 0 && index <= (1L << height);

        /// <summary>
        /// The key H_msg is applied under when a message is compressed, r || root || toByte(idx_sig, n) of RFC 8391
        /// sec. 4.1.9, built straight into the one 3n-byte array <see cref="KeyedHashFunctions.HMsg"/> reads.
        /// </summary>
        private static byte[] HMsgKey(byte[] random, byte[] root, long index, int n)
        {
            byte[] concatenated = new byte[3 * n];
            Array.Copy(random, 0, concatenated, 0, n);
            Array.Copy(root, 0, concatenated, n, n);
            int len = System.Math.Min(n, 8);
            Pack.UInt64_To_BE_Low((ulong)index, concatenated, (3 * n) - len, len);
            return concatenated;
        }

        /// <summary>Zeroize <paramref name="secret"/>, if there is one, and answer null for the field holding it.
        /// </summary>
        internal static byte[] Wipe(byte[] secret)
        {
            if (secret != null)
            {
                Arrays.ZeroMemory(secret);
            }
            return null;
        }

        /// <summary>
        /// Return <paramref name="value"/> once it is confirmed to be <paramref name="size"/> bytes long, or a
        /// freshly allocated all-zero array of that size if <paramref name="value"/> is null.
        /// </summary>
        internal static byte[] ValidateOrAllocate(byte[] value, int size, string name) =>
            XmssUtilities.ValidateOrAllocate(value, size, name);

        /// <summary>
        /// Refuse a request for a key shard of <paramref name="usageCount"/> signatures from a key with
        /// <paramref name="usagesRemaining"/> left: a shard of none, and a shard of more than the key has.
        /// </summary>
        /// <param name="usageCount">signatures asked for.</param>
        /// <param name="usagesRemaining">signatures the key has left, read under the key's own lock.</param>
        internal static void ValidateShardSize(int usageCount, long usagesRemaining)
        {
            if (usageCount < 1)
                throw new ArgumentException("cannot ask for a shard with 0 keys");
            if (usageCount > usagesRemaining)
                throw new ArgumentException("usageCount exceeds usages remaining");
        }

        internal static WotsPlus NewWotsPlus(XmssParameters parameters) =>
            new WotsPlus(NewWotsPlusParameters(parameters));

        internal static WotsPlusParameters NewWotsPlusParameters(XmssParameters parameters) =>
            new WotsPlusParameters(parameters.TreeDigestOid, parameters.TreeDigestSize);

        internal static WotsPlus NewWotsPlus(XmssMTParameters parameters) => NewWotsPlus(parameters.XmssParameters);

        /// <summary>Signs the n-byte messageDigest with the one-time key at the given OTS hash address.</summary>
        /// <remarks>
        /// The length is checked against the WOTS+ instance's own n, and this is the only place it is checked:
        /// the base-w conversion faults a digest that is too short but silently truncates one that is too long, so
        /// two different digests could sign to the same signature.
        /// </remarks>
        private static byte[][] WotsSign(WotsPlus wotsPlus, byte[] secretKeySeed, byte[] publicSeed,
            byte[] messageDigest, byte[] otsAddress)
        {
            if (messageDigest.Length != wotsPlus.Params.TreeDigestSize)
                throw new ArgumentException("size of messageDigest needs to be equal to size of digest");

            /* (re)initialize WOTS+ instance */
            byte[] wotsSecretKey = wotsPlus.GetWotsPlusSecretKey(secretKeySeed, otsAddress);
            wotsPlus.ImportKeys(wotsSecretKey, publicSeed);
            Arrays.ZeroMemory(wotsSecretKey);

            /* create WOTS+ signature */
            return wotsPlus.Sign(messageDigest, otsAddress);
        }
    }
}
