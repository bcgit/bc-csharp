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
        private int l;
        private bool isShard;
        private IList<LmsPrivateKeyParameters> keys;
        private IList<LmsSignature> sig;
        private long indexLimit;
        private long index = 0;

        private HssPublicKeyParameters publicKey;

        public HssPrivateKeyParameters(int l, IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig, long index,
            long indexLimit)
    	    :base(true)
        {
            this.l = l;
            this.keys = new List<LmsPrivateKeyParameters>(keys);
            this.sig = new List<LmsSignature>(sig);
            this.index = index;
            this.indexLimit = indexLimit;
            this.isShard = false;

            //
            // Correct Intermediate LMS values will be constructed during reset to index.
            //
            ResetKeyToIndex();
        }

        private HssPrivateKeyParameters(int l, IList<LmsPrivateKeyParameters> keys, IList<LmsSignature> sig, long index,
            long indexLimit, bool isShard)
    	    :base(true)
        {

            this.l = l;
            // this.keys =  new UnmodifiableListProxy(keys);
            // this.sig =  new UnmodifiableListProxy(sig);
            this.keys = new List<LmsPrivateKeyParameters>(keys);
            this.sig = new List<LmsSignature>(sig);
            this.index = index;
            this.indexLimit = indexLimit;
            this.isShard = isShard;
        }

        public static HssPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc)
        {
            HssPrivateKeyParameters pKey = GetInstance(privEnc);

            pKey.publicKey = HssPublicKeyParameters.GetInstance(pubEnc);

            return pKey;
        }

        public static HssPrivateKeyParameters GetInstance(object src)
        {
            if (src is HssPrivateKeyParameters hssPrivateKeyParameters)
            {
                return hssPrivateKeyParameters;
            }
            else if (src is BinaryReader binaryReader)
            {
                int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
                if (version != 0)
                    throw new Exception("unknown version for HSS private key");

                int d = BinaryReaders.ReadInt32BigEndian(binaryReader);

                long index = BinaryReaders.ReadInt64BigEndian(binaryReader);

                long maxIndex = BinaryReaders.ReadInt64BigEndian(binaryReader);

                bool limited = binaryReader.ReadBoolean();

                var keys = new List<LmsPrivateKeyParameters>();
                var signatures = new List<LmsSignature>();

                for (int t = 0; t < d; t++)
                {
                    keys.Add(LmsPrivateKeyParameters.GetInstance(src));
                }

                for (int t = 0; t < d - 1; t++)
                {
                    signatures.Add(LmsSignature.GetInstance(src));
                }

                return new HssPrivateKeyParameters(d, keys, signatures, index, maxIndex, limited);
            }
            else if (src is byte[] bytes)
            {
                BinaryReader input = null;
                try // 1.5 / 1.6 compatibility
                {
                    input = new BinaryReader(new MemoryStream(bytes, false));
                    return GetInstance(input);
                }
                finally
                {
                    if (input != null)
                    {
                        input.Close();
                    }
                }
            }
            else if (src is ArraySegment<byte> arraySegment)
            {
                BinaryReader input = null;
                try // 1.5 / 1.6 compatibility
                {
                    input = new BinaryReader(new MemoryStream(arraySegment.Array ?? Array.Empty<byte>(), arraySegment.Offset, arraySegment.Count, false));
                    return GetInstance(input);
                }
                finally
                {
                    if (input != null)
                    {
                        input.Close();
                    }
                }
            }
            else if (src is MemoryStream memoryStream)
            {
                return GetInstance(Streams.ReadAll(memoryStream));
            }

            throw new Exception($"cannot parse {src}");
        }

        public int L => l;

        public long GetIndex()
        {
            lock (this)
                return index;
        }

        public LmsParameters[] GetLmsParameters()
        {
            lock (this)
            {
                int len = keys.Count;

                LmsParameters[] parms = new LmsParameters[len];

                for (int i = 0; i < len; i++)
                {
                    LmsPrivateKeyParameters lmsPrivateKey = keys[i];

                    parms[i] = new LmsParameters(lmsPrivateKey.GetSigParameters(), lmsPrivateKey.GetOtsParameters());
                }

                return parms;
            }
        }

        internal void IncIndex()
        {
            lock (this)
            {
                index++;
            }
        }

        private static HssPrivateKeyParameters MakeCopy(HssPrivateKeyParameters privateKeyParameters)
        {
            return GetInstance(privateKeyParameters.GetEncoded());
        }

        protected void UpdateHierarchy(IList<LmsPrivateKeyParameters> newKeys, IList<LmsSignature> newSig)
        {
            lock (this)
            {
                keys = new List<LmsPrivateKeyParameters>(newKeys);
                sig = new List<LmsSignature>(newSig);
            }
        }

        public bool IsShard()
        {
            return isShard;
        }

        public long IndexLimit => indexLimit;

        public long GetUsagesRemaining()
        {
            return indexLimit - index;
        }

        LmsPrivateKeyParameters GetRootKey()
        {
            return keys[0];
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
        public HssPrivateKeyParameters ExtractKeyShard(int usageCount)
        {
            lock (this)
            {
                if (GetUsagesRemaining() < usageCount)
                    throw new ArgumentException("usageCount exceeds usages remaining in current leaf");

                long maxIndexForShard = index + usageCount;
                long shardStartIndex = index;

                //
                // Move this key's index along
                //
                index += usageCount;

                var keys = new List<LmsPrivateKeyParameters>(this.GetKeys());
                var sig = new List<LmsSignature>(this.GetSig());

                HssPrivateKeyParameters shard = MakeCopy(
                    new HssPrivateKeyParameters(l, keys, sig, shardStartIndex, maxIndexForShard, true));

                ResetKeyToIndex();

                return shard;
            }
        }

        public IList<LmsPrivateKeyParameters> GetKeys()
        {
            lock (this) return keys;
        }

        internal IList<LmsSignature> GetSig()
        {
            lock (this) return sig;
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
            if (keys[0].GetIndex() - 1 != qTreePath[0])
            {
                keys[0] = Lms.GenerateKeys(
                    originalRootKey.GetSigParameters(),
                    originalRootKey.GetOtsParameters(),
                    (int)qTreePath[0], originalRootKey.GetI(), originalRootKey.GetMasterSecret());
                changed = true;
            }

            for (int i = 1; i < qTreePath.Length; i++)
            {
                LmsPrivateKeyParameters intermediateKey = keys[i - 1];

                byte[] childI = new byte[16];
                byte[] childSeed = new byte[32];
                SeedDerive derive = new SeedDerive(
                    intermediateKey.GetI(),
                    intermediateKey.GetMasterSecret(),
                    DigestUtilities.GetDigest(intermediateKey.GetOtsParameters().DigestOid))
                {
                    Q = (int)qTreePath[i - 1],
                    J = ~1,
                };

                derive.DeriveSeed(true, childSeed, 0);
                byte[] postImage = new byte[32];
                derive.DeriveSeed(false, postImage, 0);
                Array.Copy(postImage, 0, childI, 0, childI.Length);

                //
                // Q values in LMS keys post increment after they are used.
                // For intermediate keys they will always be out by one from the derived q value (qValues[i])
                // For the end key its value will match so no correction is required.
                //
                bool lmsQMatch = (i < qTreePath.Length - 1)
                    ? qTreePath[i] == keys[i].GetIndex() - 1
                    : qTreePath[i] == keys[i].GetIndex();

                //
                // Equality is I and seed being equal and the lmsQMath.
                // I and seed are derived from this nodes parent and will change if the parent q, I, seed changes.
                //
                bool seedEquals = Arrays.AreEqual(childI, keys[i].GetI())
                    && Arrays.AreEqual(childSeed, keys[i].GetMasterSecret());

                if (!seedEquals)
                {
                    //
                    // This means the parent has changed.
                    //
                    keys[i] = Lms.GenerateKeys(
                        originalKeys[i].GetSigParameters(),
                        originalKeys[i].GetOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);

                    //
                    // Ensure post increment occurs on parent and the new public key is signed.
                    //
                    sig[i - 1] = Lms.GenerateSign((LmsPrivateKeyParameters)keys[i - 1], ((LmsPrivateKeyParameters)keys[i]).GetPublicKey().ToByteArray());
                    changed = true;
                }
                else if (!lmsQMatch)
                {
                    //
                    // Q is different so we can generate a new private key but it will have the same public
                    // key so we do not need to sign it again.
                    //
                    keys[i] = Lms.GenerateKeys(
                        originalKeys[i].GetSigParameters(),
                        originalKeys[i].GetOtsParameters(),
                        (int)qTreePath[i], childI, childSeed);
                    changed = true;
                }
            }

            if (changed)
            {
                // We mutate the HSS key here!
                UpdateHierarchy(keys, sig);
            }
        }

        public HssPublicKeyParameters GetPublicKey()
        {
            lock (this)
                return new HssPublicKeyParameters(l, GetRootKey().GetPublicKey());
        }

        internal void ReplaceConsumedKey(int d)
        {
            SeedDerive deriver = keys[d - 1].GetCurrentOtsKey().GetDerivationFunction();
            deriver.J = ~1;
            byte[] childRootSeed = new byte[32];
            deriver.DeriveSeed(true, childRootSeed, 0);
            byte[] postImage = new byte[32];
            deriver.DeriveSeed(false, postImage, 0);
            byte[] childI = new byte[16];
            Array.Copy(postImage, 0, childI, 0, childI.Length);

            var newKeys = new List<LmsPrivateKeyParameters>(keys);

            //
            // We need the parameters from the LMS key we are replacing.
            //
            LmsPrivateKeyParameters oldPk = keys[d];

            newKeys[d] = Lms.GenerateKeys(oldPk.GetSigParameters(), oldPk.GetOtsParameters(), 0, childI, childRootSeed);

            var newSig = new List<LmsSignature>(sig);

            newSig[d - 1] = Lms.GenerateSign(newKeys[d - 1], newKeys[d].GetPublicKey().ToByteArray());

            this.keys = new List<LmsPrivateKeyParameters>(newKeys);
            this.sig = new List<LmsSignature>(newSig);
        }

        public override bool Equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || GetType() != o.GetType())
            {
                return false;
            }

            HssPrivateKeyParameters that = (HssPrivateKeyParameters)o;

            if (l != that.l)
            {
                return false;
            }
            if (isShard != that.isShard)
            {
                return false;
            }
            if (indexLimit != that.indexLimit)
            {
                return false;
            }
            if (index != that.index)
            {
                return false;
            }
            if (!CompareLists(keys, that.keys))
            {
                return false;
            }
            return CompareLists(sig, that.sig);
        }

        private bool CompareLists<T>(IList<T> arr1, IList<T> arr2)
        {
            for (int i=0; i<arr1.Count && i<arr2.Count; i++)
            {
                if (!Object.Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }
            return true;
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
                    .U32Str(l)
                    .U64Str(index)
                    .U64Str(indexLimit)
                    .Boolean(isShard); // Depth

                foreach (LmsPrivateKeyParameters key in keys)
                {
                    composer.Bytes(key);
                }

                foreach (LmsSignature s in sig)
                {
                    composer.Bytes(s);
                }

                return composer.Build();
            }
        }

        public override int GetHashCode()
        {
            int result = l;
            result = 31 * result + (isShard ? 1 : 0);
            result = 31 * result + keys.GetHashCode();
            result = 31 * result + sig.GetHashCode();
            result = 31 * result + (int)(indexLimit ^ (indexLimit >> 32));
            result = 31 * result + (int)(index ^ (index >> 32));
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
            int L = this.L;

            lock (this)
            {
                Hss.RangeTestKeys(this);

                var keys = this.GetKeys();
                var sig = this.GetSig();

                nextKey = this.GetKeys()[L - 1];

                // Step 2. Stand in for sig[L-1]
                int i = 0;
                signed_pub_key = new LmsSignedPubKey[L - 1];
                while (i < L - 1)
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
                return Hss.GenerateSignature(L, context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new Exception($"unable to encode signature: {e.Message}", e);
            }
        }
    }
}
