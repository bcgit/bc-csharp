using System;
using System.Collections.Concurrent;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsPrivateKeyParameters
        : LmsKeyParameters, ILmsContextBasedSigner
    {
        private static LmsPublicKeyParameters DerivePublicKey(LmsPrivateKeyParameters privateKey)
        {
            return new LmsPublicKeyParameters(privateKey.sigParameters, privateKey.otsParameters, privateKey.FindT(1),
                privateKey.I);
        }

        // The number of tree nodes eligible for the persisted cache (nodes 1 .. CacheTopLimit - 1: the top six
        // levels of the tree). Mirrors the interned-key table size in the bc-java implementation, which defines
        // the interchange format's cache-count limit.
        private const int CacheTopLimit = 64;

        private readonly byte[] I;
        private readonly LMSigParameters sigParameters;
        private readonly LMOtsParameters otsParameters;
        private readonly int maxQ;
        private readonly byte[] masterSecret;
        // TODO Java uses a WeakHashMap
        private readonly ConcurrentDictionary<int, byte[]> tCache;
        private readonly int maxCacheR;

        private int q;
        private readonly bool m_isPlaceholder;

        //
        // These are not final because they can be generated.
        // They also do not need to be persisted.
        //
        private LmsPublicKeyParameters m_publicKey;

        public LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret)
            : base(true)
        {
            // the checks the decoder applies, so a key built directly is not one it would refuse
            if (lmsParameter == null || otsParameters == null)
                throw new ArgumentException("LMS private key needs both parameter sets");
            if (I == null || I.Length != 16)
                throw new ArgumentException("LMS key identifier I must be 16 bytes");
            if (masterSecret == null || masterSecret.Length < lmsParameter.M)
                throw new ArgumentException("master secret is less than " + lmsParameter.M);

            int twoToH = 1 << lmsParameter.H;
            if (q < 0 || maxQ < 0 || maxQ > twoToH || q > maxQ)
                throw new ArgumentException($"LMS private key q/maxQ out of range: q={q} maxQ={maxQ} 2^h={twoToH}");

            this.sigParameters = lmsParameter;
            this.otsParameters = otsParameters;
            this.q = q;
            this.I = Arrays.Clone(I);
            this.maxQ = maxQ;
            this.masterSecret = Arrays.Clone(masterSecret);
            this.maxCacheR = 1 << (sigParameters.H + 1);
            this.tCache = new ConcurrentDictionary<int, byte[]>();
        }

        /**
         * A key with no position, identifier or seed of its own - the placeholder an HSS hierarchy is
         * built with for the levels below the root, each of which resetKeyToIndex replaces from the
         * level above before the key is used. The sentinel values are deliberately ones the public
         * constructor refuses, so a placeholder can never be mistaken for a key that was merely built
         * carelessly; a subclass using this must not present the result as a usable key.
         */
        internal LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int maxQ)
            : base(true)
        {
            this.sigParameters = lmsParameter;
            this.otsParameters = otsParameters;
            this.q = -1;
            this.I = new byte[0];
            this.maxQ = maxQ;
            this.masterSecret = new byte[0];
            this.maxCacheR = 1 << (sigParameters.H + 1);
            this.tCache = new ConcurrentDictionary<int, byte[]>();
            this.m_isPlaceholder = true;
        }

        private LmsPrivateKeyParameters(LmsPrivateKeyParameters parent, int q, int maxQ)
            : this(parent, q, maxQ, 1 << parent.sigParameters.H)
        {
        }

        // TODO[lms] I, masterSecret and tCache are shared by reference with the parent. Disposal of either key
        // must account for the shards and repositioned keys derived from it, and a CalcT racing a wipe would
        // cache a node computed from zeroed input in the shared tCache.
        private LmsPrivateKeyParameters(LmsPrivateKeyParameters parent, int q, int maxQ, int maxCacheR)
            : base(true)
        {
            this.sigParameters = parent.sigParameters;
            this.otsParameters = parent.otsParameters;
            this.q = q;
            this.I = parent.I;
            this.maxQ = maxQ;
            this.masterSecret = parent.masterSecret;
            this.maxCacheR = maxCacheR;
            this.tCache = parent.tCache;
            this.m_publicKey = parent.m_publicKey;
        }

        /// <summary>
        /// This key's tree at a different one-time key. A Merkle tree is a function of the key identifier, the master
        /// secret and the parameter sets and not of q, so a key repositioned within its own tree has exactly the nodes
        /// this one has: it shares the node cache and the public key rather than rebuilding a tree that has already
        /// been built. HSS repositioning uses this in place of regenerating a component key whose identifier and seed
        /// have not changed, which otherwise costs about as much as key generation (github bc-java #2414).
        /// </summary>
        /// <param name="q">The one-time key to position at.</param>
        internal LmsPrivateKeyParameters RepositionTo(int q)
        {
            lock (this)
            {
                int twoToH = 1 << sigParameters.H;

                if (q < 0 || q > twoToH)
                    throw new ArgumentException($"LMS private key q out of range: q={q} 2^h={twoToH}", nameof(q));

                return new LmsPrivateKeyParameters(this, q, twoToH, maxCacheR);
            }
        }

        public static LmsPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc) =>
            Parse(privEnc, 0, privEnc.Length, LmsPublicKeyParameters.Parse(pubEnc));

        public static LmsPrivateKeyParameters GetInstance(object src)
        {
            if (src is LmsPrivateKeyParameters lmsPrivateKeyParameters)
                return lmsPrivateKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return Parse(stream);

            if (src is byte[] bytes)
                return Parse(bytes);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsPrivateKeyParameters Parse(BinaryReader binaryReader)
        {
            LmsPrivateKeyParameters key = ParseCore(binaryReader);

            //
            // Anything after the master secret is a cache of the top of the Merkle tree (see GetEncoded). Priming
            // it here means the first signature made after the key is decoded does not have to rebuild the whole
            // tree, which otherwise costs about as much as key generation. For a standalone key the cache is
            // optional trailing data rather than a new version, matching the bc-java interchange format - at the
            // cost of it being absent rather than malformed when a stream supplies no more bytes. Component keys
            // inside an HSS private key share their stream with the keys and signatures that follow, so "more
            // data" means nothing there - they are read via ReadKey, where the enclosing HSS encoding's version
            // dictates whether the cache field is present (bc-java github #2365).
            //
            var stream = binaryReader.BaseStream;
            if (stream.CanSeek && stream.Position < stream.Length)
            {
                ReadTreeCache(binaryReader, key);
            }

            return key;
        }

        /**
         * Read a component key from a stream shared with the other keys and signatures of an HSS private key.
         * Unlike the standalone Parse entry point, whether the tree-cache field is present is dictated by the
         * caller - from the enclosing HSS encoding's version - rather than inferred from the stream having more
         * data, which is meaningless mid-stream.
         */
        internal static LmsPrivateKeyParameters ReadKey(BinaryReader binaryReader, bool withCache)
        {
            LmsPrivateKeyParameters key = ParseCore(binaryReader);

            if (withCache)
            {
                ReadTreeCache(binaryReader, key);
            }

            return key;
        }

        private static LmsPrivateKeyParameters ParseCore(BinaryReader binaryReader)
        {
            int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (version != 0)
                throw new IOException("expected version 0 lms private key");

            LMSigParameters sigParameter = LMSigParameters.ParseByID(binaryReader);
            LMOtsParameters otsParameter = LMOtsParameters.ParseByID(binaryReader);

            byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

            int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

            int maxQ = BinaryReaders.ReadInt32BigEndian(binaryReader);

            // q selects the LM-OTS leaf and maxQ bounds it, so a stored value outside the tree is not a
            // harmless oddity: the key signs with a one-time key the public key does not commit to, and the
            // signature simply does not verify (bc-java github #2414). RFC 8554 sec. 5.3 has 0 <= q < 2^h;
            // maxQ is 2^h for a whole key and lower for a shard (ExtractKeyShard), and q == maxQ is the
            // legitimate exhausted state.
            int twoToH = 1 << sigParameter.H;
            if (q < 0 || maxQ < 0 || maxQ > twoToH || q > maxQ)
                throw new IOException(
                    $"LMS private key q/maxQ out of range: q={q} maxQ={maxQ} 2^h={twoToH}");

            int l = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (l < sigParameter.M)
            {
                // SP 800-208 sec. 6.1 requires SEED to be n bytes; GenerateKey has always required m
                throw new IOException($"secret length less than {sigParameter.M}: {l}");
            }

            // TODO[lms] Guard against stream limit if available, or at least incremental read fully
            byte[] masterSecret = BinaryReaders.ReadBytesFully(binaryReader, l);

            return new LmsPrivateKeyParameters(sigParameter, otsParameter, q, I, maxQ, masterSecret);
        }

        private static void ReadTreeCache(BinaryReader binaryReader, LmsPrivateKeyParameters key)
        {
            int cacheCount = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (cacheCount < 0 || cacheCount >= CacheTopLimit)
                throw new IOException($"tree cache node count out of range: {cacheCount}");
            if (cacheCount != 0 && (cacheCount < 3 || ((cacheCount + 1) & cacheCount) != 0))
                throw new IOException("tree cache node count is not a complete top of tree: " + cacheCount);

            int m = key.sigParameters.M;
            var stream = binaryReader.BaseStream;
            if (stream.CanSeek && (long)cacheCount * m > stream.Length - stream.Position)
                throw new IOException($"tree cache length exceeded {stream.Length - stream.Position}");

            byte[][] cachedT = new byte[cacheCount + 1][];
            for (int r = 1; r <= cacheCount; r++)
            {
                // TODO[lms] Guard against stream limit if available, or at least incremental read fully
                cachedT[r] = BinaryReaders.ReadBytesFully(binaryReader, m);
            }

            ValidateTreeCache(key, cachedT, cacheCount);

            // Entries match the state a freshly generated key reaches after its public key has been derived.
            for (int r = 1; r <= cacheCount; r++)
            {
                key.tCache[r] = cachedT[r];
            }
        }

        /**
         * Check the cached nodes are consistent with one another before they are trusted. Every node is a
         * deterministic function of I, the master secret and the parameters, so a corrupt cache is detectable
         * without rebuilding the tree: each cached interior node must be the hash of its two children, and for
         * every node up to cacheCount / 2 both children are themselves cached. A single altered node therefore
         * always fails its own parent's recomputation - including node 1, the root, whose children 2 and 3 are
         * cached - so bit rot or a partial write in the stored key is refused here rather than primed into the
         * tree, where it would change the public key the key reports or yield a signature that does not verify
         * (bc-java github #2414).
         * <p>
         * That every node is covered holds only because the caller has already refused any node count
         * that is not a complete top of tree - 2^k - 1 nodes, k at least 2. A node with no cached
         * sibling pair above it is read but never recomputed: at a count of 1 or 2 that is the root
         * itself, and at any even count it is the last node, whose parent would need the sibling the
         * count stops one short of. Every node of a complete top of tree is either recomputed from its
         * two children or is an input to its own parent's recomputation, so the guarantee above is
         * exact. This writer emits 63, or 31 for a height-5 shard, so the restriction refuses nothing
         * it produces.
         * </p>
         * <p>
         * Only interior nodes are recomputed. A cached node at or beyond 2^h is a leaf, and deriving one costs
         * an LM-OTS public key - which is the work the cache exists to avoid; a corrupt leaf is still caught,
         * by its cached parent. The check is (cacheCount - 1) / 2 hashes, independent of h.
         * </p>
         */
        private static void ValidateTreeCache(LmsPrivateKeyParameters key, byte[][] cachedT, int cacheCount)
        {
            int twoToH = 1 << key.sigParameters.H;
            var digest = LmsUtilities.GetDigest(key.sigParameters);

            for (int r = 1; r < twoToH && 2 * r + 1 <= cacheCount; r++)
            {
                LmsUtilities.ByteArray(key.I, digest);
                LmsUtilities.U32Str(r, digest);
                LmsUtilities.U16Str((short)Lms.D_INTR, digest);
                LmsUtilities.ByteArray(cachedT[2 * r], digest);
                LmsUtilities.ByteArray(cachedT[2 * r + 1], digest);

                byte[] node = new byte[digest.GetDigestSize()];
                digest.DoFinal(node, 0);

                if (!Arrays.AreEqual(node, cachedT[r]))
                    throw new IOException($"LMS private key tree cache inconsistent at node {r}");
            }
        }

        internal static LmsPrivateKeyParameters Parse(Stream stream) =>
            BinaryReaders.Parse(Parse, stream, leaveOpen: true);

        internal static LmsPrivateKeyParameters Parse(byte[] buf) => Parse(buf, 0, buf.Length);

        internal static LmsPrivateKeyParameters Parse(byte[] buf, int off, int len) =>
            BinaryReaders.Parse(Parse, buf, off, len, "LMS private key");

        internal static LmsPrivateKeyParameters Parse(byte[] buf, int off, int len, LmsPublicKeyParameters publicKey)
        {
            LmsPrivateKeyParameters pKey = Parse(buf, off, len);

            // The public key that arrived alongside the private one is authoritative, so where the tree
            // already carries its root node in the cache it costs nothing to confirm the two agree. That
            // catches a tree cache which is internally consistent but belongs to a different key - the one
            // corruption the node-by-node check in ValidateTreeCache cannot see. It is deliberately skipped
            // when the root is not cached: recomputing it there means rebuilding the whole tree, which is the
            // work the cache exists to avoid (bc-java github #2414).
            if (publicKey != null)
            {
                // cross-check rather than adopt, as the HSS twin does; the root only where it is cached
                if (!Arrays.AreEqual(pKey.I, publicKey.GetI()) ||
                    pKey.SigParameters.ID != publicKey.GetSigParameters().ID ||
                    pKey.OtsParameters.ID != publicKey.GetOtsParameters().ID)
                {
                    throw new IOException("LMS public key does not match the private key");
                }

                byte[] cachedRoot = pKey.PeekRootT();

                if (cachedRoot != null && !Arrays.AreEqual(cachedRoot, publicKey.GetT1()))
                    throw new IOException("LMS private key tree cache does not match the public key");
            }

            lock (pKey)
            {
                pKey.m_publicKey = publicKey;
            }

            return pKey;
        }

        /// <summary>
        /// Derive the identifier and master seed of the tree below the current one-time key of this key
        /// (RFC 8554 sec. 6.1) - the child an HSS hierarchy hangs off leaf q. The index is not advanced.
        /// </summary>
        /// <returns>{ I of the child tree, master seed of the child tree }.</returns>
#if NETCOREAPP2_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        internal ValueTuple<byte[], byte[]> DeriveChildKey()
#else
        internal Tuple<byte[], byte[]> DeriveChildKey()
#endif
        {
            lock (this)
            {
                CheckDisposed();

                if (q >= maxQ)
                    throw new ExhaustedPrivateKeyException("ots private key exhausted");

                return LmsEngine.DeriveChildKey(otsParameters, I, masterSecret, q);
            }
        }

        /// <summary>
        /// Derive the identifier and master seed of the tree below one-time key <paramref name="q"/> of this key,
        /// which need not be the current one: HSS repositioning asks for the child at the leaf its index names. The
        /// index is not advanced. The derivation runs under the lock so that the secret is read whole.
        /// </summary>
        /// <returns>{ I of the child tree, master seed of the child tree }.</returns>
#if NETCOREAPP2_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        internal ValueTuple<byte[], byte[]> DeriveChildKey(int q)
#else
        internal Tuple<byte[], byte[]> DeriveChildKey(int q)
#endif
        {
            // maxQ rather than 2^h: the two coincide for a whole key, but a leaf beyond a shard's usage limit
            // belongs to some other holder's range, and deriving its child is a misconfiguration to refuse.
            if (q < 0 || q >= maxQ)
                throw new ArgumentOutOfRangeException(nameof(q));

            lock (this)
            {
                CheckDisposed();

                return LmsEngine.DeriveChildKey(otsParameters, I, masterSecret, q);
            }
        }

        /// <summary>
        /// Whether this key is the tree with the given identifier and master seed. A Merkle tree is a function of
        /// those and the parameter sets, so two keys agreeing on them are the same tree at (possibly) different
        /// one-time keys.
        /// </summary>
        internal bool HasIdentity(byte[] I, byte[] masterSecret)
        {
            lock (this)
            {
                CheckDisposed();

                return Arrays.AreEqual(this.I, I) && Arrays.FixedTimeEquals(this.masterSecret, masterSecret);
            }
        }

        /// <summary>Return the private key index number (the q value).</summary>
        public int GetIndex()
        {
            lock (this) return q;
        }

        internal void IncIndex()
        {
            lock (this)
            {
                q++;
            }
        }

        public LmsContext GenerateLmsContext()
        {
            if (m_isPlaceholder)
                throw new InvalidOperationException("placeholder only");

            // Step 1.
            LMSigParameters lmsParameter = SigParameters;

            // Step 2
            int h = lmsParameter.H;
            int q;

            //
            // The index is claimed before the context is handed out, so a one-time key is never issued
            // twice even if the caller then abandons the context.
            //
            lock (this)
            {
                CheckDisposed();

                if (this.q >= maxQ)
                    throw new ExhaustedPrivateKeyException("ots private key exhausted");

                q = this.q++;
            }

            int i = 0;
            int r = (1 << h) + q;
            byte[][] path = new byte[h][];

            while (i < h)
            {
                int tmp = (r / (1 << i)) ^ 1;

                path[i++] = FindT(tmp);
            }

            return new LMOtsPrivateKey(otsParameters, I, q, masterSecret).GetSignatureContext(sigParameters, path);
        }

        public byte[] GenerateSignature(LmsContext context)
        {
            try
            {
                return Lms.GenerateSign(context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unable to encode signature", e);
            }
        }

        /**
         * Return a key that can be used usageCount times.
         * <p>
         * Note: this will use the range [index...index + usageCount) for the current key.
         * </p>
         *
         * @param usageCount the number of usages the key should have.
         * @return a key based on the current key that can be used usageCount times.
         */
        public LmsPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                if (usageCount < 0)
                    throw new ArgumentOutOfRangeException(nameof(usageCount), "cannot be negative");
                if (usageCount > maxQ - q)
                    throw new ArgumentException("exceeds usages remaining", nameof(usageCount));

                int shardIndex = q;
                int shardIndexLimit = q + usageCount;

                // Move this key's index along
                q = shardIndexLimit;

                return new LmsPrivateKeyParameters(this, shardIndex, shardIndexLimit);
            }
        }

        [Obsolete("Use 'SigParameters' instead")]
        public LMSigParameters GetSigParameters() => sigParameters;

        public LMSigParameters SigParameters => sigParameters;

        [Obsolete("Use 'OtsParameters' instead")]
        public LMOtsParameters GetOtsParameters() => otsParameters;

        public LMOtsParameters OtsParameters => otsParameters;

        public byte[] GetI() => Arrays.Clone(I);

        // TODO[api] Remove. A seed handed out alone is a second copy of the key with no index attached - the state
        // duplication SP 800-208 rules out - and GetEncoded carries the index, usage limit and tree cache with it.
        [Obsolete("Use 'GetEncoded' instead")]
        public byte[] GetMasterSecret()
        {
            byte[] rv = Arrays.Clone(masterSecret);

            // Clone first, check second: a disposal that lands in between has set the flag before
            // it clears the array, so a stale copy is never handed out.
            CheckDisposed();

            return rv;
        }

        public int IndexLimit => maxQ;

        // TODO[api] Only needs 'int'
        public long GetUsagesRemaining() => IndexLimit - GetIndex();

        public LmsPublicKeyParameters GetPublicKey()
        {
            if (m_isPlaceholder)
                throw new InvalidOperationException("placeholder only");

            lock (this)
            {
                if (m_publicKey == null)
                {
                    m_publicKey = DerivePublicKey(this);
                }
                return m_publicKey;
            }
        }

        /**
         * The root node if it is already in the cache, otherwise null. Unlike GetPublicKey() this never
         * computes it, so a caller can cross-check the root against an authoritative public key without
         * paying for a tree rebuild when there is nothing cached (bc-java github #2414).
         */
        internal byte[] PeekRootT() => tCache.TryGetValue(1, out byte[] rootT) ? rootT : null;

        internal byte[] FindT(int r)
        {
            if (r >= maxCacheR)
                return CalcT(r);

            return tCache.GetOrAdd(r, CalcT);
        }

        private byte[] CalcT(int r)
        {
            LMSigParameters sigParameters = SigParameters;

            var tDigest = LmsUtilities.GetDigest(sigParameters);

            int h = sigParameters.H;

            int twoToh = 1 << h;

            byte[] T = new byte[tDigest.GetDigestSize()];

            // r is a base 1 index.

            if (r >= twoToh)
            {
                //
                // These can be pre generated at the time of key generation and held within the private key.
                // However it will cost memory to have them stick around.
                //
                CheckDisposed();

                LmsUtilities.ByteArray(I, tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_LEAF, tDigest);

                byte[] K = LMOts.LmsOtsGeneratePublicKey(otsParameters, I, r - twoToh, masterSecret);

                LmsUtilities.ByteArray(K, tDigest);
            }
            else
            {
                byte[] t2r = FindT(2 * r);
                byte[] t2rPlus1 = FindT(2 * r + 1);

                LmsUtilities.ByteArray(I, tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_INTR, tDigest);
                LmsUtilities.ByteArray(t2r, tDigest);
                LmsUtilities.ByteArray(t2rPlus1, tDigest);
            }

            tDigest.DoFinal(T, 0);
            return T;
        }

        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is LmsPrivateKeyParameters that
                && this.GetIndex() == that.GetIndex()
                && this.maxQ == that.maxQ
                && Arrays.AreEqual(this.I, that.I)
                && Objects.Equals(this.sigParameters, that.sigParameters)
                && Objects.Equals(this.otsParameters, that.otsParameters)
                && Arrays.FixedTimeEquals(this.masterSecret, that.masterSecret);
        }

        public override int GetHashCode()
        {
            //
            // Deliberately not GetPublicKey().GetHashCode(): the root is only there if the tree cache
            // holds it, so on a freshly generated or decoded key that builds the whole Merkle tree -
            // 2^h LM-OTS public keys - from an implicit call no caller expects to cost anything. It is
            // also independent of q, so a key's hash does not move as it signs, and of the master
            // secret, so no function of the seed is handed out. Equal keys agree on every field used
            // here, so the Equals() contract holds.
            //
            int hc = Objects.GetHashCode(sigParameters);
            hc = 31 * hc + Objects.GetHashCode(otsParameters);
            hc = 31 * hc + maxQ;
            hc = 31 * hc + Arrays.GetHashCode(I);
            return hc;
        }

        public override byte[] GetEncoded()
        {
            CheckDisposed();

            int q = GetIndex();

            //
            // NB there is no formal specification for the encoding of private keys.
            // It is implementation dependent.
            //
            // Format:
            //     version u32                 (0)
            //     type u32
            //     otstype u32
            //     I u8x16
            //     q u32
            //     maxQ u32
            //     master secret Length u32
            //     master secret u8[]
            //     tree cache node count u32   (n; the top-of-tree nodes 1..n) - optional
            //     tree cache nodes u8[]       (n * SigParameters.M bytes) - optional
            //
            // The tree cache carries the top of the Merkle tree so that the first signature made after the key
            // is decoded does not have to rebuild the whole tree - which otherwise costs about as much as key
            // generation (see bc-java github #2365). The nodes are a deterministic function of I, the master
            // secret and the parameters and are independent of q, so persisting them leaks nothing the (already
            // encoded) master secret does not. The cache is appended after the master secret rather than
            // announced by a new version number, matching the bc-java interchange format. bc-java's pre-cache
            // decoders stop at the master secret and ignore the trailing bytes; bc-csharp's do not: release 2.7.0
            // rejects trailing data in an LMS private key encoding, and every earlier release rejects the HSS
            // version 1 that announces cached component keys, so keys written by this release cannot be read by
            // those.
            //

            int cacheTop = System.Math.Min(CacheTopLimit, maxCacheR);

            Composer composer = Composer.Compose()
                .U32Str(0) // version
                .U32Str(sigParameters.ID) // type
                .U32Str(otsParameters.ID) // ots type
                .Bytes(I) // I at 16 bytes
                .U32Str(q) // q
                .U32Str(maxQ) // maximum q
                .U32Str(masterSecret.Length) // length of master secret.
                .Bytes(masterSecret) // the master secret
                .U32Str(cacheTop - 1); // number of cached tree nodes (nodes 1 .. cacheTop-1)

            for (int r = 1; r < cacheTop; r++)
            {
                composer.Bytes(FindT(r)); // top-of-tree node r
            }

            return composer.Build();
        }

        private void CheckDisposed()
        {
            // TODO[lms] Implement IDisposable instead of Java's Destroyable and check liveness here
        }
    }
}
