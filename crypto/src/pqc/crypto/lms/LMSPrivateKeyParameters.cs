using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsPrivateKeyParameters
        : LmsKeyParameters, ILmsContextBasedSigner
    {
        private static CacheKey T1 = new CacheKey(1);
        private static CacheKey[] internedKeys = new CacheKey[129];

        static LmsPrivateKeyParameters()
        {
            internedKeys[1] = T1;
            for (int i = 2; i < internedKeys.Length; i++)
            {
                internedKeys[i] = new CacheKey(i);
            }
        }

        private byte[] I;
        private LMSigParameters parameters;
        private LMOtsParameters otsParameters;
        private int maxQ;
        private byte[] masterSecret;
        private Dictionary<CacheKey, byte[]> tCache;
        private int maxCacheR;
        private IDigest tDigest;

        private int q;
        private readonly bool m_isPlaceholder;

        //
        // These are not final because they can be generated.
        // They also do not need to be persisted.
        //
        private LmsPublicKeyParameters publicKey;

        public LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret)
            : this(lmsParameter, otsParameters, q, I, maxQ, masterSecret, false)
        {
        }

        internal LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret, bool isPlaceholder)
            : base(true)
        {
            this.parameters = lmsParameter;
            this.otsParameters = otsParameters;
            this.q = q;
            this.I = Arrays.Clone(I);
            this.maxQ = maxQ;
            this.masterSecret = Arrays.Clone(masterSecret);
            this.maxCacheR = 1 << (parameters.H + 1);
            this.tCache = new Dictionary<CacheKey, byte[]>();
            this.tDigest = DigestUtilities.GetDigest(lmsParameter.DigestOid);
            this.m_isPlaceholder = isPlaceholder;
        }

        private LmsPrivateKeyParameters(LmsPrivateKeyParameters parent, int q, int maxQ)
            : base(true)
        {
            this.parameters = parent.parameters;
            this.otsParameters = parent.otsParameters;
            this.q = q;
            this.I = parent.I;
            this.maxQ = maxQ;
            this.masterSecret = parent.masterSecret;
            this.maxCacheR = 1 << parameters.H;
            this.tCache = parent.tCache;
            this.tDigest = DigestUtilities.GetDigest(parameters.DigestOid);
            this.publicKey = parent.publicKey;
        }

        public static LmsPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc)
        {
            LmsPrivateKeyParameters pKey = GetInstance(privEnc);
        
            pKey.publicKey = LmsPublicKeyParameters.GetInstance(pubEnc);

            return pKey;
        }

        public static LmsPrivateKeyParameters GetInstance(object src)
        {
            if (src is LmsPrivateKeyParameters lmsPrivateKeyParameters)
            {
                return lmsPrivateKeyParameters;
            }
            else if (src is BinaryReader binaryReader)
            {
                int version = BinaryReaders.ReadInt32BigEndian(binaryReader);
                if (version != 0)
                    throw new Exception("unknown version for LMS private key");

                int sigParamType = BinaryReaders.ReadInt32BigEndian(binaryReader);
                LMSigParameters sigParameter = LMSigParameters.GetParametersByID(sigParamType);

                int otsParamType = BinaryReaders.ReadInt32BigEndian(binaryReader);
                LMOtsParameters otsParameter = LMOtsParameters.GetParametersByID(otsParamType);

                byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

                int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

                int maxQ = BinaryReaders.ReadInt32BigEndian(binaryReader);

                int l = BinaryReaders.ReadInt32BigEndian(binaryReader);
                if (l < 0)
                    throw new Exception("secret length less than zero");

                byte[] masterSecret = BinaryReaders.ReadBytesFully(binaryReader, l);

                return new LmsPrivateKeyParameters(sigParameter, otsParameter, q, I, maxQ, masterSecret);
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
            else if (src is MemoryStream memoryStream)
            {
                return GetInstance(Streams.ReadAll(memoryStream));
            }

            throw new ArgumentException($"cannot parse {src}");
        }


        internal LMOtsPrivateKey GetCurrentOtsKey()
        {
            lock (this)
            {
                if (q >= maxQ)
                    throw new Exception("ots private keys expired");

                return new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
            }
        }

        /**
         * Return the key index (the q value).
         *
         * @return private key index number.
         */
        public int GetIndex()
        {
            lock (this)
                return q;
        }

        internal void IncIndex()
        {
            lock (this) 
                q++;
        }

        public LmsContext GenerateLmsContext()
        {
            // Step 1.
            LMSigParameters lmsParameter = this.GetSigParameters();

            // Step 2
            int h = lmsParameter.H;
            int q = GetIndex();
            LMOtsPrivateKey otsPk = GetNextOtsPrivateKey();

            int i = 0;
            int r = (1 << h) + q;
            byte[][] path = new byte[h][];

            while (i < h)
            {
                int tmp = (r / (1 << i)) ^ 1;

                path[i] = this.FindT(tmp);
                i++;
            }

            return otsPk.GetSignatureContext(this.GetSigParameters(), path);
        }

        public byte[] GenerateSignature(LmsContext context)
        {
            try
            {
                return Lms.GenerateSign(context).GetEncoded();
            }
            catch (IOException e)
            {
                throw new Exception($"unable to encode signature: {e.Message}", e);
            }
        }

        internal LMOtsPrivateKey GetNextOtsPrivateKey()
        {
            if (m_isPlaceholder)
                throw new Exception("placeholder only");

            lock (this)
            {
                if (q >= maxQ)
                    throw new Exception("ots private key exhausted");

                LMOtsPrivateKey otsPrivateKey = new LMOtsPrivateKey(otsParameters, I, q, masterSecret);
                IncIndex();
                return otsPrivateKey;
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
                if (q + usageCount >= maxQ)
                    throw new ArgumentException("usageCount exceeds usages remaining");

                LmsPrivateKeyParameters keyParameters = new LmsPrivateKeyParameters(this, q, q + usageCount);
                q += usageCount;

                return keyParameters;
            }
        }

        public LMSigParameters GetSigParameters()
        {
            return parameters;
        }

        public LMOtsParameters GetOtsParameters()
        {
            return otsParameters;
        }

        public byte[] GetI()
        {
            return Arrays.Clone(I);
        }

        public byte[] GetMasterSecret()
        {
            return Arrays.Clone(masterSecret);
        }

        public long GetUsagesRemaining()
        {
            return maxQ - q;
        }

        public LmsPublicKeyParameters GetPublicKey()
        {
            if (m_isPlaceholder)
                throw new Exception("placeholder only");

            lock (this)
            {
                if (publicKey == null)
                {
                    publicKey = new LmsPublicKeyParameters(parameters, otsParameters, this.FindT(T1), I);
                }
                return publicKey;
            }
        }

        internal byte[] FindT(int r)
        {
            if (r < maxCacheR)
            {
                return FindT(r < internedKeys.Length ? internedKeys[r] : new CacheKey(r));
            }

            return CalcT(r);
        }

        private byte[] FindT(CacheKey key)
        {
            lock (tCache)
            {
                if (tCache.TryGetValue(key, out byte[] t))
                    return t;

                return tCache[key] = CalcT(key.index);
            }
        }

        private byte[] CalcT(int r)
        {
            int h = this.GetSigParameters().H;

            int twoToh = 1 << h;

            byte[] T;

            // r is a base 1 index.

            if (r >= twoToh)
            {
                LmsUtilities.ByteArray(this.GetI(), tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_LEAF, tDigest);
                //
                // These can be pre generated at the time of key generation and held within the private key.
                // However it will cost memory to have them stick around.
                //
                byte[] K = LMOts.LmsOtsGeneratePublicKey(this.GetOtsParameters(), this.GetI(), (r - twoToh),
                    this.GetMasterSecret());

                LmsUtilities.ByteArray(K, tDigest);
                T = new byte[tDigest.GetDigestSize()];
                tDigest.DoFinal(T, 0);
                return T;
            }

            byte[] t2r = FindT(2 * r);
            byte[] t2rPlus1 = FindT((2 * r + 1));

            LmsUtilities.ByteArray(this.GetI(), tDigest);
            LmsUtilities.U32Str(r, tDigest);
            LmsUtilities.U16Str((short)Lms.D_INTR, tDigest);
            LmsUtilities.ByteArray(t2r, tDigest);
            LmsUtilities.ByteArray(t2rPlus1, tDigest);
            T = new byte[tDigest.GetDigestSize()];
            tDigest.DoFinal(T, 0);

            return T;
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

            LmsPrivateKeyParameters that = (LmsPrivateKeyParameters)o;

            if (q != that.q)
            {
                return false;
            }
            if (maxQ != that.maxQ)
            {
                return false;
            }
            if (!Arrays.AreEqual(I, that.I))
            {
                return false;
            }
            if (parameters != null ? !parameters.Equals(that.parameters) : that.parameters != null)
            {
                return false;
            }
            if (otsParameters != null ? !otsParameters.Equals(that.otsParameters) : that.otsParameters != null)
            {
                return false;
            }
            if (!Arrays.AreEqual(masterSecret, that.masterSecret))
            {
                return false;
            }

            //
            // Only compare public keys if they both exist.
            // Otherwise we would trigger the creation of one or both of them
            //
            if (publicKey != null && that.publicKey != null)
            {
                return publicKey.Equals(that.publicKey);
            }

            return true;
        }

        public override int GetHashCode()
        {
            int result = q;
            result = 31 * result + Arrays.GetHashCode(I);
            result = 31 * result + (parameters != null ? parameters.GetHashCode() : 0);
            result = 31 * result + (otsParameters != null ? otsParameters.GetHashCode() : 0);
            result = 31 * result + maxQ;
            result = 31 * result + Arrays.GetHashCode(masterSecret);
            result = 31 * result + (publicKey != null ? publicKey.GetHashCode() : 0);
            return result;
        }

        public override byte[] GetEncoded()
        {
            //
            // NB there is no formal specification for the encoding of private keys.
            // It is implementation dependent.
            //
            // Format:
            //     version u32
            //     type u32
            //     otstype u32
            //     I u8x16
            //     q u32
            //     maxQ u32
            //     master secret Length u32
            //     master secret u8[]
            //

            return Composer.Compose()
                .U32Str(0) // version
                .U32Str(parameters.ID) // type
                .U32Str(otsParameters.ID) // ots type
                .Bytes(I) // I at 16 bytes
                .U32Str(q) // q
                .U32Str(maxQ) // maximum q
                .U32Str(masterSecret.Length) // length of master secret.
                .Bytes(masterSecret) // the master secret
                .Build();
        }

        class CacheKey
        {
            internal int index;

            public CacheKey(int index)
            {
                this.index = index;
            }

            public override int GetHashCode()
            {
                return index;
            }

            public override bool Equals(Object o)
            {
                if (o is CacheKey)
                {
                    return ((CacheKey)o).index == this.index;
                }

                return false;
            }
        }
    }
}