using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class HssPrivateKeyParameters
        : LmsKeyParameters, ILmsContextBasedSigner
    {
        private readonly int m_level;
        private readonly bool m_isShard;
        private IList<LmsPrivateKeyParameters> m_keys;
        private IList<LmsSignature> m_sig;
        private readonly long m_indexLimit;
        private long m_index = 0;

        private HssPublicKeyParameters m_publicKey;

        public HssPrivateKeyParameters(int l, IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig, long index,
            long indexLimit)
    	    : base(true)
        {
            m_level = l;
            m_isShard = false;
            m_keys = new List<LmsPrivateKeyParameters>(keys);
            m_sig = new List<LmsSignature>(sig);
            m_index = index;
            m_indexLimit = indexLimit;

            //
            // Correct Intermediate LMS values will be constructed during reset to index.
            //
            ResetKeyToIndex();
        }

        private HssPrivateKeyParameters(int l, IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig, long index,
            long indexLimit, bool isShard)
    	    :base(true)
        {

            m_level = l;
            m_isShard = isShard;
            m_keys = new List<LmsPrivateKeyParameters>(keys);
            m_sig = new List<LmsSignature>(sig);
            m_index = index;
            m_indexLimit = indexLimit;
        }

        public static HssPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc)
        {
            HssPrivateKeyParameters pKey = GetInstance(privEnc);
            pKey.m_publicKey = HssPublicKeyParameters.GetInstance(pubEnc);
            return pKey;
        }

        public static HssPrivateKeyParameters GetInstance(object src)
        {
            if (src is HssPrivateKeyParameters hssPrivateKeyParameters)
                return hssPrivateKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static HssPrivateKeyParameters Parse(BinaryReader binaryReader)
        {
            int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (version != 0)
                throw new Exception("unknown version for HSS private key");

            int d = BinaryReaders.ReadInt32BigEndian(binaryReader);

            long index = BinaryReaders.ReadInt64BigEndian(binaryReader);

            long maxIndex = BinaryReaders.ReadInt64BigEndian(binaryReader);

            bool limited = binaryReader.ReadBoolean();

            var keys = new List<LmsPrivateKeyParameters>(d);
            for (int t = 0; t < d; t++)
            {
                keys.Add(LmsPrivateKeyParameters.Parse(binaryReader));
            }

            var signatures = new List<LmsSignature>(d - 1);
            for (int t = 1; t < d; t++)
            {
                signatures.Add(LmsSignature.Parse(binaryReader));
            }

            return new HssPrivateKeyParameters(d, keys, signatures, index, maxIndex, limited);
        }

        [Obsolete("Use 'Level' instead")]
        public int L => m_level;

        public int Level => m_level;

        public long GetIndex()
        {
            lock (this) return m_index;
        }

        public LmsParameters[] GetLmsParameters()
        {
            lock (this)
            {
                int len = m_keys.Count;

                LmsParameters[] parameters = new LmsParameters[len];

                for (int i = 0; i < len; i++)
                {
                    LmsPrivateKeyParameters lmsPrivateKey = m_keys[i];

                    parameters[i] = new LmsParameters(lmsPrivateKey.GetSigParameters(), lmsPrivateKey.GetOtsParameters());
                }

                return parameters;
            }
        }

        internal void IncIndex()
        {
            lock (this) m_index++;
        }

        private static HssPrivateKeyParameters MakeCopy(HssPrivateKeyParameters privateKeyParameters)
        {
            return GetInstance(privateKeyParameters.GetEncoded());
        }

        protected void UpdateHierarchy(IList<LmsPrivateKeyParameters> newKeys, IList<LmsSignature> newSig)
        {
            lock (this)
            {
                m_keys = new List<LmsPrivateKeyParameters>(newKeys);
                m_sig = new List<LmsSignature>(newSig);
            }
        }

        public bool IsShard() => m_isShard;

        public long IndexLimit => m_indexLimit;

        public long GetUsagesRemaining() => m_indexLimit - m_index;

        internal LmsPrivateKeyParameters GetRootKey() => m_keys[0];

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
                if (GetUsagesRemaining() < usageCount)
                    throw new ArgumentException("usageCount exceeds usages remaining in current leaf");

                long maxIndexForShard = m_index + usageCount;
                long shardStartIndex = m_index;

                //
                // Move this key's index along
                //
                m_index += usageCount;

                var keys = new List<LmsPrivateKeyParameters>(this.GetKeys());
                var sig = new List<LmsSignature>(this.GetSig());

                HssPrivateKeyParameters shard = MakeCopy(
                    new HssPrivateKeyParameters(m_level, keys, sig, shardStartIndex, maxIndexForShard, true));

                ResetKeyToIndex();

                return shard;
            }
        }

        public IList<LmsPrivateKeyParameters> GetKeys()
        {
            lock (this) return m_keys;
        }

        internal IList<LmsSignature> GetSig()
        {
            lock (this) return m_sig;
        }

        /**
         * Reset to index will ensure that all LMS keys are correct for a given HSS index value.
         * Normally LMS keys updated in sync with their parent HSS key but in cases of sharding
         * the normal monotonic updating does not apply and the state of the LMS keys needs to be
         * reset to match the current HSS index.
         */
        void ResetKeyToIndex()
        {
            // Extract the original keys
            var originalKeys = GetKeys();

            long[] qTreePath = new long[originalKeys.Count];
            long q = GetIndex();

            for (int t = originalKeys.Count - 1; t >= 0; t--)
            {
                LMSigParameters sigParameters = originalKeys[t].GetSigParameters();
                int mask = (1 << sigParameters.H) - 1;
                qTreePath[t] = q & mask;
                q >>= sigParameters.H;
            }

            bool changed = false;

            // LMSPrivateKeyParameters[] keys =  originalKeys.ToArray(new LMSPrivateKeyParameters[originalKeys.Count]);//  new LMSPrivateKeyParameters[originalKeys.Size()];
            // LMSSignature[] sig = this.sig.toArray(new LMSSignature[this.sig.Count]);//   new LMSSignature[originalKeys.Size() - 1];
            //

            LmsPrivateKeyParameters originalRootKey = this.GetRootKey();

            //
            // We need to replace the root key to a new q value.
            //
            if (m_keys[0].GetIndex() - 1 != qTreePath[0])
            {
                m_keys[0] = Lms.GenerateKeys(
                    originalRootKey.GetSigParameters(),
                    originalRootKey.GetOtsParameters(),
                    (int)qTreePath[0], originalRootKey.GetI(), originalRootKey.GetMasterSecret());
                changed = true;
            }

            for (int i = 1; i < qTreePath.Length; i++)
            {
                LmsPrivateKeyParameters intermediateKey = m_keys[i - 1];
                int n = intermediateKey.GetOtsParameters().N;

                byte[] childI = new byte[16];
                byte[] childSeed = new byte[n];
                SeedDerive derive = new SeedDerive(
                    intermediateKey.GetI(),
                    intermediateKey.GetMasterSecret(),
                    LmsUtilities.GetDigest(intermediateKey.GetOtsParameters()))
                {
                    Q = (int)qTreePath[i - 1],
                    J = ~1,
                };

                derive.DeriveSeed(true, childSeed, 0);
                byte[] postImage = new byte[n];
                derive.DeriveSeed(false, postImage, 0);
                Array.Copy(postImage, 0, childI, 0, childI.Length);

                //
                // Q values in LMS keys post increment after they are used.
                // For intermediate keys they will always be out by one from the derived q value (qValues[i])
                // For the end key its value will match so no correction is required.
                //
                bool lmsQMatch = (i < qTreePath.Length - 1)
                    ? qTreePath[i] == m_keys[i].GetIndex() - 1
                    : qTreePath[i] == m_keys[i].GetIndex();

                //
                // Equality is I and seed being equal and the lmsQMath.
                // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
                //
                bool seedEquals = Arrays.AreEqual(childI, m_keys[i].GetI())
                    && Arrays.AreEqual(childSeed, m_keys[i].GetMasterSecret());

                if (!seedEquals)
                {
                    //
                    // This means the parent has changed.
                    //
                    m_keys[i] = Lms.GenerateKeys(
                        originalKeys[i].GetSigParameters(),
                        originalKeys[i].GetOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);

                    //
                    // Ensure post increment occurs on parent and the new public key is signed.
                    //
                    m_sig[i - 1] = Lms.GenerateSign((LmsPrivateKeyParameters)m_keys[i - 1], ((LmsPrivateKeyParameters)m_keys[i]).GetPublicKey().ToByteArray());
                    changed = true;
                }
                else if (!lmsQMatch)
                {
                    //
                    // Q is different so we can generate a new private key but it will have the same public
                    // key so we do not need to sign it again.
                    //
                    m_keys[i] = Lms.GenerateKeys(
                        originalKeys[i].GetSigParameters(),
                        originalKeys[i].GetOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);
                    changed = true;
                }
            }

            if (changed)
            {
                // We mutate the HSS key here!
                UpdateHierarchy(m_keys, m_sig);
            }
        }

        public HssPublicKeyParameters GetPublicKey()
        {
            lock (this)
                return new HssPublicKeyParameters(m_level, GetRootKey().GetPublicKey());
        }

        internal void ReplaceConsumedKey(int d)
        {
            LMOtsPrivateKey currentOtsKey = m_keys[d - 1].GetCurrentOtsKey();
            int n = currentOtsKey.Parameters.N;

            SeedDerive deriver = currentOtsKey.GetDerivationFunction();
            deriver.J = ~1;
            byte[] childRootSeed = new byte[n];
            deriver.DeriveSeed(true, childRootSeed, 0);
            byte[] postImage = new byte[n];
            deriver.DeriveSeed(false, postImage, 0);
            byte[] childI = new byte[16];
            Array.Copy(postImage, 0, childI, 0, childI.Length);

            var newKeys = new List<LmsPrivateKeyParameters>(m_keys);

            //
            // We need the parameters from the LMS key we are replacing.
            //
            LmsPrivateKeyParameters oldPk = m_keys[d];

            newKeys[d] = Lms.GenerateKeys(oldPk.GetSigParameters(), oldPk.GetOtsParameters(), 0, childI, childRootSeed);

            var newSig = new List<LmsSignature>(m_sig);

            newSig[d - 1] = Lms.GenerateSign(newKeys[d - 1], newKeys[d].GetPublicKey().ToByteArray());

            this.m_keys = new List<LmsPrivateKeyParameters>(newKeys);
            this.m_sig = new List<LmsSignature>(newSig);
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;

            return obj is HssPrivateKeyParameters that
                && this.m_level == that.m_level
                && this.m_isShard == that.m_isShard
                && this.m_indexLimit == that.m_indexLimit
                && this.m_index == that.m_index
                && CompareLists(this.m_keys, that.m_keys)
                && CompareLists(this.m_sig, that.m_sig);
        }

        public override byte[] GetEncoded()
        {
            lock (this)
            {
                //
                // Private keys are implementation dependent.
                //

                Composer composer = Composer.Compose()
                    .U32Str(0) // Version.
                    .U32Str(m_level)
                    .U64Str(m_index)
                    .U64Str(m_indexLimit)
                    .Boolean(m_isShard); // Depth

                foreach (LmsPrivateKeyParameters key in m_keys)
                {
                    composer.Bytes(key);
                }

                foreach (LmsSignature s in m_sig)
                {
                    composer.Bytes(s);
                }

                return composer.Build();
            }
        }

        public override int GetHashCode()
        {
            int result = m_level;
            result = 31 * result + m_isShard.GetHashCode();
            result = 31 * result + m_keys.GetHashCode();
            result = 31 * result + m_sig.GetHashCode();
            result = 31 * result + m_indexLimit.GetHashCode();
            result = 31 * result + m_index.GetHashCode();
            return result;
        }

        protected object Clone()
        {
            return MakeCopy(this);
        }

        public LmsContext GenerateLmsContext()
        {
            LmsSignedPubKey[] signed_pub_key;
            LmsPrivateKeyParameters nextKey;
            int level = Level;

            lock (this)
            {
                Hss.RangeTestKeys(this);

                var keys = this.GetKeys();
                var sig = this.GetSig();

                nextKey = this.GetKeys()[level - 1];

                // Step 2. Stand in for sig[level-1]
                int i = 0;
                signed_pub_key = new LmsSignedPubKey[level - 1];
                while (i < level - 1)
                {
                    signed_pub_key[i] = new LmsSignedPubKey(sig[i], keys[i + 1].GetPublicKey());
                    ++i;
                }

                //
                // increment the index.
                //
                this.IncIndex();
            }

            return nextKey.GenerateLmsContext().WithSignedPublicKeys(signed_pub_key);
        }

        public byte[] GenerateSignature(LmsContext context)
        {
            try
            {
                return Hss.GenerateSignature(Level, context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new Exception($"unable to encode signature: {e.Message}", e);
            }
        }

        private static bool CompareLists<T>(IList<T> arr1, IList<T> arr2)
        {
            for (int i = 0; i < arr1.Count && i < arr2.Count; i++)
            {
                if (!Object.Equals(arr1[i], arr2[i]))
                    return false;
            }
            return true;
        }
    }
}
