using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make sealed
    public class HssPrivateKeyParameters
        : LmsKeyParameters, ILmsContextBasedSigner
    {
        /// <summary>
        /// The component keys of an HSS hierarchy together with the chaining signatures that bind them: the public
        /// key of level i is signed by the key of level i - 1, and that signature is Sig[i - 1].
        /// </summary>
        /// <remarks>
        /// The two move together - replacing a consumed tree replaces both its key and the signature above it - so
        /// they are held as one immutable object and published by a single reference write. A reader that has the
        /// reference has a coherent pair of them without taking the key's monitor, and without a window in which
        /// one has been replaced and the other has not.
        /// </remarks>
        private sealed class Hierarchy
        {
            internal static Hierarchy Copy(IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig)
            {
                var keysCopy = new LmsPrivateKeyParameters[keys.Count];
                keys.CopyTo(keysCopy, 0);

                var sigCopy = new LmsSignature[sig.Count];
                sig.CopyTo(sigCopy, 0);

                return new Hierarchy(keysCopy, sigCopy);
            }

            private readonly LmsPrivateKeyParameters[] m_keys;
            private readonly LmsSignature[] m_sig;

            /// <summary>Takes ownership of the arrays, which must not be modified afterwards.</summary>
            internal Hierarchy(LmsPrivateKeyParameters[] keys, LmsSignature[] sig)
            {
                m_keys = keys;
                m_sig = sig;

                // Built once with the snapshot rather than per call, since the snapshot cannot change
                Keys = CollectionUtilities.ReadOnly(keys);
                Sig = CollectionUtilities.ReadOnly(sig);
            }

            internal IList<LmsPrivateKeyParameters> Keys { get; }

            internal IList<LmsSignature> Sig { get; }

            internal int Count => m_keys.Length;

            internal LmsPrivateKeyParameters GetKey(int index) => m_keys[index];

            internal LmsSignature GetSig(int index) => m_sig[index];

            /// <summary>The parameter sets of every level, in order from the root.</summary>
            internal LmsParameters[] GetLmsParameters()
            {
                var parameters = new LmsParameters[m_keys.Length];
                for (int i = 0; i < m_keys.Length; i++)
                {
                    parameters[i] = m_keys[i].LmsParameters;
                }
                return parameters;
            }

            internal LmsPrivateKeyParameters[] CopyKeys() => (LmsPrivateKeyParameters[])m_keys.Clone();

            internal LmsSignature[] CopySig() => (LmsSignature[])m_sig.Clone();

            /// <summary>
            /// Copy both arrays, unless a previous call already did, for a caller that does not know whether it has
            /// anything to change until it finds the first thing.
            /// </summary>
            internal void EnsureCopies(ref LmsPrivateKeyParameters[] keys, ref LmsSignature[] sig)
            {
                if (keys == null)
                {
                    keys = CopyKeys();
                    sig = CopySig();
                }
            }

            internal bool HasUnconstructedLevel() =>
                Array.IndexOf(m_keys, null) >= 0 || Array.IndexOf(m_sig, null) >= 0;

            /// <summary>The component keys, each as a length-prefixed encoding, followed by the chaining
            /// signatures the same way.</summary>
            internal void EncodeTo(Composer composer)
            {
                foreach (LmsPrivateKeyParameters key in m_keys)
                {
                    composer.Bytes(key);
                }

                foreach (LmsSignature s in m_sig)
                {
                    composer.Bytes(s);
                }
            }
        }

        private readonly int m_level;
        private readonly bool m_isShard;
        // Replaced, never modified; written under this key's monitor and read without it (see Hierarchy).
        private Hierarchy m_hierarchy;
        private readonly long m_indexLimit;
        private long m_index = 0;

        /// <summary>
        /// Generate an HSS private key: a root LMS key drawn from the <paramref name="parameters"/>' random source,
        /// with the lower trees derived from it when the key is first positioned at index 0.
        /// </summary>
        internal static HssPrivateKeyParameters Generate(HssKeyGenerationParameters parameters)
        {
            //
            // LmsPrivateKey can derive and hold the public key so we just use an array of those.
            //
            LmsPrivateKeyParameters[] keys = new LmsPrivateKeyParameters[parameters.Depth];
            LmsSignature[] sig = new LmsSignature[parameters.Depth - 1];

            var rootLms = parameters.GetLmsParameters(0);

            //
            // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
            // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
            // index of zero. Rather than repeat the same reset-to-index logic in this static method.
            //

            keys[0] = LmsPrivateKeyParameters.Generate(rootLms, parameters.Random);

            long hssKeyMaxIndex = 1L << rootLms.LMSigParameters.H;

            for (int t = 1; t < keys.Length; t++)
            {
                var lms = parameters.GetLmsParameters(t);
                int h = lms.LMSigParameters.H;

                keys[t] = LmsPrivateKeyParameters.CreatePlaceholder(lms, maxQ: 1 << h);

                hssKeyMaxIndex <<= h;
            }

            // if this has happened we're trying to generate a really large key
            // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
            if (hssKeyMaxIndex <= 0L)
            {
                hssKeyMaxIndex = long.MaxValue;
            }

            return new HssPrivateKeyParameters(parameters.Depth, keys, sig, 0, hssKeyMaxIndex);
        }

        public HssPrivateKeyParameters(LmsPrivateKeyParameters key, long index, long indexLimit)
            : base(true)
        {
            m_level = 1;
            m_isShard = false;
            m_hierarchy = new Hierarchy(new[] { key }, Array.Empty<LmsSignature>());
            m_index = index;
            m_indexLimit = indexLimit;

            //
            // Correct Intermediate LMS values will be constructed during reset to index.
            //
            ResetKeyToIndex();
        }

        public HssPrivateKeyParameters(int l, IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig, long index,
            long indexLimit)
            : base(true)
        {
            // the same shape the decoder requires; resetKeyToIndex below indexes both lists against l
            if (l < 1 || l > 8)    // RFC 8554, Section 6.
                throw new ArgumentException("L value of HSS private key out of range: " + l, nameof(l));
            if (keys.Count != l)
                throw new ArgumentException("HSS private key needs one component key per level", nameof(keys));
            if (sig.Count != l - 1)
            {
                throw new ArgumentException("HSS private key needs one chaining signature per level below the root",
                    nameof(sig));
            }
            if (index < 0 || indexLimit < 0 || index > indexLimit)
            {
                throw new ArgumentException(
                    $"HSS private key index out of range: index={index} indexLimit={indexLimit}", nameof(index));
            }

            m_level = l;
            m_isShard = false;
            m_hierarchy = Hierarchy.Copy(keys, sig);
            m_index = index;
            m_indexLimit = indexLimit;

            //
            // Correct Intermediate LMS values will be constructed during reset to index.
            //
            ResetKeyToIndex();

            // a null level is legitimate on the way in, for the reset above to fill, but not on the way out
            if (CurrentHierarchy.HasUnconstructedLevel())
                throw new ArgumentException("HSS private key has a level that was left unconstructed");
        }

        /// <summary>Takes the hierarchy as it stands, which is immutable and so may be shared with the key it was
        /// taken from.</summary>
        private HssPrivateKeyParameters(int l, Hierarchy hierarchy, long index, long indexLimit, bool isShard)
            : base(true)
        {
            m_level = l;
            m_hierarchy = hierarchy;
            m_index = index;
            m_indexLimit = indexLimit;
            m_isShard = isShard;
        }

        private Hierarchy CurrentHierarchy => Volatile.Read(ref m_hierarchy);

        public static HssPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc) =>
            Parse(privEnc, 0, privEnc.Length, HssPublicKeyParameters.Parse(pubEnc));

        /// <summary>
        /// The HSS index and the component keys' one-time indices are two records of the same position in the key, and
        /// a decoded key whose records disagree is refused. RFC 8554 sec. 1 requires each one - time key to be used
        /// once; a stored key whose index has been rolled back while its component keys stayed advanced - a partial
        /// write, a restore from backup, a buggy storage layer - would otherwise sign a second message under a one-time
        /// key already used, and that signature would verify, so nothing would surface it. The check is the identity
        /// the two records satisfy: a level below the last contributes(q - 1) leaves of the levels beneath it, because
        /// its q has already advanced past the subtree it signed, and the last level contributes its q directly.
        /// Verified against every index of a two-level key and across a level boundary of a three-level one (github
        /// bc-java #2414).
        /// </summary>
        /// <remarks>
        /// Applied at decode only. The constructor is also reached from the hierarchy update, which rebuilds lower
        /// levels and is momentarily inconsistent by design; corrupt stored state can only arrive here.
        /// </remarks>
        private static void CheckIndexAgainstKeys(int d, LmsPrivateKeyParameters[] keys, long index)
        {
            long implied = keys[d - 1].GetIndex();
            int shift = 0;

            for (int i = d - 2; i >= 0; --i)
            {
                shift += keys[i + 1].SigParameters.H;
                if (shift >= 63)
                {
                    // taller than the 64-bit index can address, so the two records cannot be compared
                    return;
                }
                implied += (keys[i].GetIndex() - 1L) << shift;
            }

            if (implied != index)
                throw new IOException(
                    $"HSS private key index {index} does not match the component key indices, which imply {implied}");
        }

        public static HssPrivateKeyParameters GetInstance(object src)
        {
            if (src is HssPrivateKeyParameters hssPrivateKeyParameters)
                return hssPrivateKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return Parse(stream);

            if (src is byte[] bytes)
                return Parse(bytes);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static HssPrivateKeyParameters Parse(BinaryReader binaryReader)
        {
            int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (version != 0 && version != 1)
                throw new IOException("unknown version for HSS private key");

            int d = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (d < 1 || d > 8) // RFC 8554, Section 6.
                throw new IOException($"d value of HSS private key out of range: {d}");

            long index = BinaryReaders.ReadInt64BigEndian(binaryReader);

            long maxIndex = BinaryReaders.ReadInt64BigEndian(binaryReader);

            if (index < 0 || maxIndex < 0 || index > maxIndex)
                throw new IOException(
                    $"HSS private key index out of range: index={index} maxIndex={maxIndex}");

            bool limited = binaryReader.ReadBoolean();

            // Read once here, so every component key is held to the same limit
            int maxSeedLength = LmsPrivateKeyParameters.GetMaxSeedLength();

            var keys = new LmsPrivateKeyParameters[d];
            for (int t = 0; t < d; t++)
            {
                // The component keys share this stream with the keys and signatures that follow, so whether each
                // one carries the tree-cache field cannot be inferred from the stream having more data - the
                // encoding version says: a version 0 encoding predates the tree cache and its component keys end
                // at the master secret, a version 1 component always carries the cache field (bc-java github
                // #2365).
                keys[t] = LmsPrivateKeyParameters.ParseComponentKey(binaryReader, maxSeedLength,
                    withCache: version != 0);
            }

            var signatures = new LmsSignature[d - 1];
            for (int t = 1; t < d; t++)
            {
                signatures[t - 1] = LmsSignature.Parse(binaryReader);
            }

            CheckIndexAgainstKeys(d, keys, index);

            return new HssPrivateKeyParameters(d, new Hierarchy(keys, signatures), index, maxIndex, limited);
        }

        internal static HssPrivateKeyParameters Parse(Stream stream) =>
            BinaryReaders.Parse(Parse, stream, leaveOpen: true);

        internal static HssPrivateKeyParameters Parse(byte[] buf) => Parse(buf, 0, buf.Length);

        internal static HssPrivateKeyParameters Parse(byte[] buf, int off, int len) =>
            BinaryReaders.Parse(Parse, buf, off, len, "HSS private key");

        internal static HssPrivateKeyParameters Parse(byte[] buf, int off, int len, HssPublicKeyParameters publicKey)
        {
            HssPrivateKeyParameters pKey = Parse(buf, off, len);

            // The public key that arrived alongside the private one is authoritative, so where the root tree
            // already carries its root node in the cache it costs nothing to confirm the two agree. That
            // catches a tree cache which is internally consistent but belongs to a different key - the one
            // corruption the node-by-node check in LmsPrivateKeyParameters cannot see. It is deliberately
            // skipped when the root is not cached: recomputing it there means rebuilding the whole tree,
            // which is the work the cache exists to avoid (bc-java github #2414).
            if (publicKey != null)
            {
                // cross-check rather than adopt, as the LMS twin does: the level, root identifier and parameter
                // sets unconditionally, the root node only where it is cached
                LmsPrivateKeyParameters root = pKey.GetRootKey();
                LmsPublicKeyParameters lmsPublicKey = publicKey.LmsPublicKey;

                if (publicKey.Level != pKey.Level ||
                    !Arrays.AreEqual(root.GetI(), lmsPublicKey.GetI()) ||
                    root.SigParameters.ID != lmsPublicKey.GetSigParameters().ID ||
                    root.OtsParameters.ID != lmsPublicKey.GetOtsParameters().ID)
                {
                    throw new IOException("HSS public key does not match the private key");
                }

                byte[] cachedRoot = root.PeekRootT();
                if (cachedRoot != null && !Arrays.AreEqual(cachedRoot, lmsPublicKey.GetT1()))
                    throw new IOException("HSS private key tree cache does not match the public key");
            }

            return pKey;
        }

        [Obsolete("Use 'Level' instead")]
        public int L => m_level;

        public int Level => m_level;

        public long GetIndex()
        {
            lock (this) return m_index;
        }

        public LmsParameters[] GetLmsParameters() => CurrentHierarchy.GetLmsParameters();

        internal void IncIndex()
        {
            lock (this)
            {
                m_index++;
            }
        }

        /// <summary>
        /// Advance the key past its current index without signing with it, replacing exhausted lower trees as a
        /// signature would. Used by the tests to walk a key through the RFC 8554 vectors.
        /// </summary>
        internal void IncrementIndex()
        {
            // The HSS index and the bottom key's q are two records of one position, claimed together (as in
            // GenerateLmsContext)
            lock (this)
            {
                RangeTestKeys();
                IncIndex();
                CurrentHierarchy.GetKey(m_level - 1).IncIndex();
            }
        }

        private static HssPrivateKeyParameters MakeCopy(HssPrivateKeyParameters privateKeyParameters) =>
            Parse(privateKeyParameters.GetEncoded());

        // TODO[api] Remove. Nothing calls this: the hierarchy is replaced by the methods that build it, which
        // hold the monitor across the read and the write and take ownership of what they built. Sealing the
        // class (see above) removes it in any case.
        protected void UpdateHierarchy(IList<LmsPrivateKeyParameters> newKeys, IList<LmsSignature> newSig)
        {
            lock (this)
            {
                Volatile.Write(ref m_hierarchy, Hierarchy.Copy(newKeys, newSig));
            }
        }

        public bool IsShard() => m_isShard;

        public long IndexLimit => m_indexLimit;

        public long GetUsagesRemaining() => IndexLimit - GetIndex();

        internal LmsPrivateKeyParameters GetRootKey() => GetKey(0);

        /**
         * Return a key that can be used usageCount times.
         * <p>
         * Note: this will use the range [index...index + usageCount) for the current key.
         * </p>
         *
         * @param usageCount the number of usages the key should have.
         * @return a key based on the current key that can be used usageCount times.
         */
        public HssPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                CheckDisposed();

                if (usageCount < 0)
                    throw new ArgumentOutOfRangeException(nameof(usageCount), "cannot be negative");
                if (usageCount > m_indexLimit - m_index)
                    throw new ArgumentException("exceeds usages remaining in current leaf", nameof(usageCount));

                long shardIndex = m_index;
                long shardIndexLimit = m_index + usageCount;

                // Move this key's index along
                m_index = shardIndexLimit;

                // The hierarchy is shared with this key rather than copied: MakeCopy re-parses the encoding, so
                // the shard that escapes has component keys of its own either way.
                HssPrivateKeyParameters shard = MakeCopy(new HssPrivateKeyParameters(m_level, CurrentHierarchy,
                    shardIndex, shardIndexLimit, isShard: true));

                ResetKeyToIndex();

                return shard;
            }
        }

        internal LmsPrivateKeyParameters GetKey(int index) => CurrentHierarchy.GetKey(index);

        // Two reads of the hierarchy, so a caller that needs the keys and the signatures over them to belong to one
        // snapshot has to take the pair in one step, or check that it did not change between the two.
        // TODO[api] Remove: bc-java's promoted API keeps both package-private, and nothing outside needs either
        public IList<LmsPrivateKeyParameters> GetKeys() => CurrentHierarchy.Keys;

        internal IList<LmsSignature> GetSig() => CurrentHierarchy.Sig;

        /// <summary>
        /// Reset to index will ensure that all LMS keys are correct for a given HSS index value. Normally LMS keys are
        /// updated in sync with their parent HSS key but in cases of sharding the normal monotonic updating does not
        /// apply and the state of the LMS keys needs to be reset to match the current HSS index.
        /// </summary>
        /// <remarks>
        /// Should only be called under the monitor (lock) or during construction before the instance escapes.
        /// </remarks>
        private void ResetKeyToIndex()
        {
            // Extract the original keys
            Hierarchy oldHierarchy = CurrentHierarchy;

            long[] qTreePath = new long[oldHierarchy.Count];
            long q = GetIndex();

            for (int t = oldHierarchy.Count - 1; t >= 0; t--)
            {
                LMSigParameters sigParameters = oldHierarchy.GetKey(t).SigParameters;
                int mask = (1 << sigParameters.H) - 1;
                qTreePath[t] = q & mask;
                q >>= sigParameters.H;
            }

            // Copied when the first level is found to need replacing, so a key already in sync with its index -
            // the usual case, since only sharding and a stale supplied index put it out of sync - copies nothing
            LmsPrivateKeyParameters[] newKeys = null;
            LmsSignature[] newSig = null;

            LmsPrivateKeyParameters rootKey = oldHierarchy.GetKey(0);

            // We need to replace the root key to a new q value; the last level reads the derived
            // value itself, which for a single level hierarchy is the root.
            //
            bool rootQMatch = (qTreePath.Length > 1)
                ? qTreePath[0] == rootKey.GetIndex() - 1
                : qTreePath[0] == rootKey.GetIndex();

            if (!rootQMatch)
            {
                //
                // Only the position moves - the root's identifier, seed and parameter sets are its own
                // and cannot have changed - so this is the same tree at a different one-time key, and
                // the repositioned key keeps the tree the root has already built.
                //
                CheckNotRewound(0, rootKey.GetIndex() - (qTreePath.Length > 1 ? 1 : 0), qTreePath[0]);

                rootKey = rootKey.RepositionTo((int)qTreePath[0]);

                oldHierarchy.EnsureCopies(ref newKeys, ref newSig);
                newKeys[0] = rootKey;
            }

            // The level above the one being examined, as it now stands: it is the only one that can already
            // have been replaced, since each level is replaced on its own pass
            LmsPrivateKeyParameters parentKey = rootKey;

            for (int i = 1; i < qTreePath.Length; i++)
            {
                var child = parentKey.DeriveChildKey((int)qTreePath[i - 1]);
                byte[] childI = child.Item1;
                byte[] childSeed = child.Item2;

                LmsPrivateKeyParameters oldKey = oldHierarchy.GetKey(i);
                LmsPrivateKeyParameters newKey = oldKey;

                //
                // Q values in LMS keys post increment after they are used.
                // For intermediate keys they will always be out by one from the derived q value (qValues[i])
                // For the end key its value will match so no correction is required.
                //
                bool lmsQMatch = (i < qTreePath.Length - 1)
                    ? qTreePath[i] == oldKey.GetIndex() - 1
                    : qTreePath[i] == oldKey.GetIndex();

                //
                // Equality is I and seed being equal and the lmsQMath.
                // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
                //
                bool seedEquals = oldKey.HasIdentity(childI, childSeed);

                if (!seedEquals)
                {
                    //
                    // This means the parent has changed.
                    //
                    oldHierarchy.EnsureCopies(ref newKeys, ref newSig);
                    newKey = ReplaceLevel(newKeys, newSig, i, oldKey.LmsParameters, q: (int)qTreePath[i], childI, childSeed);
                }
                else if (!lmsQMatch)
                {
                    //
                    // Q is different, but seedEquals says the identifier and seed are not, so this is
                    // the same tree at a different one-time key: reposition within it rather than
                    // rebuild it. The public key is unchanged either way, so the chaining signature
                    // above it still stands and does not need making again.
                    //
                    CheckNotRewound(i, oldKey.GetIndex() - (i < qTreePath.Length - 1 ? 1 : 0), qTreePath[i]);

                    newKey = oldKey.RepositionTo((int)qTreePath[i]);

                    oldHierarchy.EnsureCopies(ref newKeys, ref newSig);
                    newKeys[i] = newKey;
                }

                parentKey = newKey;
            }

            if (newKeys != null)
            {
                // We mutate the HSS key here! Under the caller's monitor, per the contract above.
                Volatile.Write(ref m_hierarchy, new Hierarchy(newKeys, newSig));
            }
        }

        /// <summary>
        /// A component key whose identifier and seed are unchanged is the same tree, and moving it back within that
        /// tree would hand out one-time keys it has already used; a signature made with one verifies, so nothing
        /// later would surface it. Every route here that the key controls moves forward or stays put -
        /// ExtractKeyShard advances the index, and a decoded key's index already agrees with its component keys -
        /// so a position behind the key can only be a stale index supplied to the public constructor, and it is
        /// refused rather than acted on.
        /// </summary>
        /// <param name="level">The level being repositioned, for the message.</param>
        /// <param name="currentQ">The one-time key the level has advanced to (its q, less the post-increment of a
        /// level that has signed the one beneath it).</param>
        /// <param name="targetQ">The one-time key the index asks for.</param>
        private static void CheckNotRewound(int level, long currentQ, long targetQ)
        {
            if (targetQ < currentQ)
            {
                throw new InvalidOperationException(
                    $"HSS private key index would move level {level} back from one-time key {currentQ} to {targetQ}");
            }
        }

        public HssPublicKeyParameters GetPublicKey()
        {
            lock (this)
                return new HssPublicKeyParameters(m_level, GetRootKey().GetPublicKey());
        }

        /// <summary>
        /// Check the key has an index left to sign with, and replace every lower tree that has used all of its
        /// one-time keys with the next one its parent derives (RFC 8554 sec. 6.1).
        /// </summary>
        // TODO[api] Make private once Hss.RangeTestKeys goes
        internal void RangeTestKeys()
        {
            lock (this)
            {
                if (m_index >= m_indexLimit)
                {
                    throw new ExhaustedPrivateKeyException(
                        "hss private key" + (m_isShard ? " shard" : "") + " is exhausted");
                }

                int L = m_level;
                int d = L;
                Hierarchy hierarchy = CurrentHierarchy;
                while (true)
                {
                    LmsPrivateKeyParameters key = hierarchy.GetKey(d - 1);

                    // The whole tree, not the key's own maxQ: a component key given a narrower limit keeps it, and
                    // replacing the level would hand back a full tree in its place
                    // (IndexAndComponentIndexClaimedTogether). >= rather than ==: an index above 2^h steps straight
                    // over an equality test (bc-java github #2414). Decode now rejects such a q, so this is belt
                    // and braces.
                    if (key.GetIndex() < 1 << key.SigParameters.H)
                        break;

                    if (--d == 0)
                    {
                        throw new ExhaustedPrivateKeyException("hss private key" + (m_isShard ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                    }
                }

                if (d < L)
                {
                    ReplaceExhaustedKeys(d);
                }
            }
        }

        /// <summary>
        /// Replace the exhausted trees, at levels <paramref name="d"/> and below, with fresh ones. Each is derived
        /// from the current one-time key of the level above it, and has its public key signed by that key.
        /// </summary>
        /// <remarks>
        /// Should only be called under the monitor (lock): the new trees are derived from the hierarchy this reads,
        /// so the read and the write have to be one step. The rebuilt levels are published as a single hierarchy,
        /// since one rebuilt only as far as level i pairs the fresh tree at level i with the signature over the
        /// exhausted one it replaced.
        /// </remarks>
        internal void ReplaceExhaustedKeys(int d)
        {
            Hierarchy oldHierarchy = CurrentHierarchy;

            var newKeys = oldHierarchy.CopyKeys();
            var newSig = oldHierarchy.CopySig();

            for (; d < m_level; ++d)
            {
                // Each level below the first takes its parent from the level rebuilt on the previous pass
                var childKey = newKeys[d - 1].DeriveChildKey();
                byte[] childI = childKey.Item1;
                byte[] childSeed = childKey.Item2;

                // The replacement keeps the parameters of the key it replaces
                LmsPrivateKeyParameters oldKey = newKeys[d];

                ReplaceLevel(newKeys, newSig, d, oldKey.LmsParameters, q: 0, childI, childSeed);
            }

            // The replaced keys and the signatures over them reach readers together
            Volatile.Write(ref m_hierarchy, new Hierarchy(newKeys, newSig));
        }

        /// <summary>
        /// Replace level d of a hierarchy: an LMS private key positioned at index q(RFC 8554 sec. 5.2, Algorithm 5)
        /// built from the identifier and seed the level above derived for it, together with the chaining signature
        /// over its public key, which the level above makes by consuming one of its one - time keys(sec. 6.1).
        /// Writes keys[d] and sig[d - 1]; keys[d - 1] must already be the level above.
        /// </summary>
        private static LmsPrivateKeyParameters ReplaceLevel(LmsPrivateKeyParameters[] keys, LmsSignature[] sig, int d,
            LmsParameters lmsParameters, int q, byte[] I, byte[] masterSecret)
        {
            //
            // RFC 8554 recommends the digest used in LMS and LMOTS be of the same strength to protect against
            // attackers going after the weaker of the two digests. This is not enforced here!
            //
            LmsPrivateKeyParameters key = new LmsPrivateKeyParameters(lmsParameters, q, I,
                1 << lmsParameters.LMSigParameters.H, masterSecret);

            LmsContext context = keys[d - 1].GenerateLmsContext();

            key.GetPublicKey().UpdateDigest(context);

            keys[d] = key;
            sig[d - 1] = LmsEngine.GenerateSign(context);

            return key;
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;

            if (!(obj is HssPrivateKeyParameters that) ||
                this.m_level != that.m_level ||
                this.m_isShard != that.m_isShard ||
                this.m_indexLimit != that.m_indexLimit)
            {
                return false;
            }

            //
            // The index and the hierarchy both move as consumed trees are replaced, and they move
            // together, so read each key's pair in one synchronized block to get a snapshot no
            // unsynchronized reader could tear. The hierarchy is immutable and replaced rather than
            // modified, so a captured reference stays a coherent view after the lock drops. Neither
            // monitor is held while the other is taken, so a.Equals(b) racing b.Equals(a) cannot
            // deadlock.
            //
            long thisIndex;
            Hierarchy thisHierarchy;
            lock (this)
            {
                thisIndex = this.m_index;
                thisHierarchy = CurrentHierarchy;
            }

            long thatIndex;
            Hierarchy thatHierarchy;
            lock (that)
            {
                thatIndex = that.m_index;
                thatHierarchy = that.CurrentHierarchy;
            }

            return thisIndex == thatIndex
                && CompareLists(thisHierarchy.Keys, thatHierarchy.Keys)
                && CompareLists(thisHierarchy.Sig, thatHierarchy.Sig);
        }

        public override byte[] GetEncoded()
        {
            lock (this)
            {
                //
                // Private keys are implementation dependent.
                //

                CheckDisposed();

                // Version 1: the component keys carry the mandatory tree-cache field their GetEncoded appends; a
                // version 0 encoding (any release before the tree cache) carries them without it. The version
                // dispatch in Parse is what keeps the shared stream unambiguous.
                Composer composer = Composer.Compose()
                    .U32Str(1) // Version.
                    .U32Str(m_level)
                    .U64Str(m_index)
                    .U64Str(m_indexLimit)
                    .Boolean(m_isShard); // Depth

                CurrentHierarchy.EncodeTo(composer);

                return composer.Build();
            }
        }

        public override int GetHashCode()
        {
            //
            // Deliberately not GetPublicKey().GetHashCode(): that reaches the root key's tree, which is
            // only built if the node cache does not already hold it - 2^h LM-OTS public keys from an
            // implicit call no caller expects to cost anything. The fields used here are the ones that
            // do not move as the key signs: the root key material is fixed (ResetKeyToIndex only
            // repositions it, and LmsPrivateKeyParameters.GetHashCode is itself index-independent),
            // whereas index, keys and sig all change. Equal keys agree on all of these, so the
            // Equals() contract holds.
            //
            int hc = m_level;
            hc = 31 * hc + (m_isShard ? 1 : 0);
            hc = 31 * hc + m_indexLimit.GetHashCode();
            hc = 31 * hc + GetRootKey().GetHashCode();
            return hc;
        }

        protected object Clone()
        {
            return MakeCopy(this);
        }

        public LmsContext GenerateLmsContext()
        {
            LmsSignedPubKey[] signed_pub_key;
            LmsContext context;
            int level = Level;

            // the HSS index and the bottom key's q are two records of one position: claim both here,
            // bottom key first so an exhausted one leaves each untouched.
            lock (this)
            {
                CheckDisposed();

                RangeTestKeys();

                // After the range test, which replaces the levels it finds exhausted
                Hierarchy hierarchy = CurrentHierarchy;

                LmsPrivateKeyParameters nextKey = hierarchy.GetKey(level - 1);

                // Step 2. Stand in for sig[level-1]
                int i = 0;
                signed_pub_key = new LmsSignedPubKey[level - 1];
                while (i < level - 1)
                {
                    signed_pub_key[i] = new LmsSignedPubKey(hierarchy.GetSig(i),
                        hierarchy.GetKey(i + 1).GetPublicKey());
                    ++i;
                }

                context = nextKey.GenerateLmsContext();

                //
                // increment the index.
                //
                this.IncIndex();
            }

            return LmsEngine.WithSignedPublicKeys(context, signed_pub_key);
        }

        public byte[] GenerateSignature(LmsContext context) => LmsEngine.GenerateHssSignature(Level, context);

        private void CheckDisposed()
        {
            // TODO[lms] Implement IDisposable instead of Java's Destroyable and check liveness here
        }

        private static bool CompareLists<T>(IList<T> arr1, IList<T> arr2)
        {
            if (ReferenceEquals(arr1, arr2))
                return true;
            if (arr1.Count != arr2.Count)
                return false;
            for (int i = 0; i < arr1.Count; ++i)
            {
                if (!Object.Equals(arr1[i], arr2[i]))
                    return false;
            }
            return true;
        }
    }
}
