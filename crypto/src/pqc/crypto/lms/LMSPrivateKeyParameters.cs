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

        private byte[] I;
        private LMSigParameters sigParameters;
        private LMOtsParameters otsParameters;
        private int maxQ;
        private byte[] masterSecret;
        // TODO Java uses a WeakHashMap
        private ConcurrentDictionary<int, byte[]> tCache;
        private int maxCacheR;
        private IDigest tDigest;

        private int q;
        private readonly bool m_isPlaceholder;

        //
        // These are not final because they can be generated.
        // They also do not need to be persisted.
        //
        private LmsPublicKeyParameters m_publicKey;

        public LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret)
            : this(lmsParameter, otsParameters, q, I, maxQ, masterSecret, false)
        {
        }

        internal LmsPrivateKeyParameters(LMSigParameters lmsParameter, LMOtsParameters otsParameters, int q, byte[] I,
            int maxQ, byte[] masterSecret, bool isPlaceholder)
            : base(true)
        {
            this.sigParameters = lmsParameter;
            this.otsParameters = otsParameters;
            this.q = q;
            this.I = Arrays.Clone(I);
            this.maxQ = maxQ;
            this.masterSecret = Arrays.Clone(masterSecret);
            this.maxCacheR = 1 << (sigParameters.H + 1);
            this.tCache = new ConcurrentDictionary<int, byte[]>();
            this.tDigest = LmsUtilities.GetDigest(lmsParameter);
            this.m_isPlaceholder = isPlaceholder;
        }

        private LmsPrivateKeyParameters(LmsPrivateKeyParameters parent, int q, int maxQ)
            : base(true)
        {
            this.sigParameters = parent.sigParameters;
            this.otsParameters = parent.otsParameters;
            this.q = q;
            this.I = parent.I;
            this.maxQ = maxQ;
            this.masterSecret = parent.masterSecret;
            this.maxCacheR = 1 << sigParameters.H;
            this.tCache = parent.tCache;
            this.tDigest = LmsUtilities.GetDigest(sigParameters);
            this.m_publicKey = parent.m_publicKey;
        }

        public static LmsPrivateKeyParameters GetInstance(byte[] privEnc, byte[] pubEnc)
        {
            LmsPrivateKeyParameters pKey = GetInstance(privEnc);
            pKey.m_publicKey = LmsPublicKeyParameters.GetInstance(pubEnc);
            return pKey;
        }

        public static LmsPrivateKeyParameters GetInstance(object src)
        {
            if (src is LmsPrivateKeyParameters lmsPrivateKeyParameters)
                return lmsPrivateKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsPrivateKeyParameters Parse(BinaryReader binaryReader)
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

        internal LMOtsPrivateKey GetCurrentOtsKey()
        {
            lock (this)
            {
                if (q >= maxQ)
                    // TODO ExhaustedPrivateKeyException
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
            LMSigParameters lmsParameter = SigParameters;

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

                path[i++] = FindT(tmp);
            }

            return otsPk.GetSignatureContext(sigParameters, path);
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

        [Obsolete("Use 'SigParameters' instead")]
        public LMSigParameters GetSigParameters() => sigParameters;

        public LMSigParameters SigParameters => sigParameters;

        [Obsolete("Use 'OtsParameters' instead")]
        public LMOtsParameters GetOtsParameters() => otsParameters;

        public LMOtsParameters OtsParameters => otsParameters;

        public byte[] GetI() => Arrays.Clone(I);

        public byte[] GetMasterSecret() => Arrays.Clone(masterSecret);

        public long GetUsagesRemaining() => maxQ - GetIndex();

        public LmsPublicKeyParameters GetPublicKey()
        {
            if (m_isPlaceholder)
                throw new Exception("placeholder only");

            return Objects.EnsureSingletonInitialized(ref m_publicKey, this, DerivePublicKey);
        }

        internal byte[] FindT(int r)
        {
            // TODO Should be > instead of >= ?
            if (r >= maxCacheR)
                return CalcT(r);

            return tCache.GetOrAdd(r, CalcT);
        }

        private byte[] CalcT(int r)
        {
            int h = sigParameters.H;

            int twoToh = 1 << h;

            byte[] T = new byte[tDigest.GetDigestSize()];

            // r is a base 1 index.

            if (r >= twoToh)
            {
                LmsUtilities.ByteArray(I, tDigest);
                LmsUtilities.U32Str(r, tDigest);
                LmsUtilities.U16Str((short)Lms.D_LEAF, tDigest);
                //
                // These can be pre generated at the time of key generation and held within the private key.
                // However it will cost memory to have them stick around.
                //
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
                && this.q == that.q
                && this.maxQ == that.maxQ
                && Arrays.AreEqual(this.I, that.I)
                && Objects.Equals(this.sigParameters, that.sigParameters)
                && Objects.Equals(this.otsParameters, that.otsParameters)
                && Arrays.AreEqual(this.masterSecret, that.masterSecret);
        }

        public override int GetHashCode()
        {
            int result = q;
            result = 31 * result + maxQ;
            result = 31 * result + Arrays.GetHashCode(I);
            result = 31 * result + Objects.GetHashCode(sigParameters);
            result = 31 * result + Objects.GetHashCode(otsParameters);
            result = 31 * result + Arrays.GetHashCode(masterSecret);
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
                .U32Str(sigParameters.ID) // type
                .U32Str(otsParameters.ID) // ots type
                .Bytes(I) // I at 16 bytes
                .U32Str(q) // q
                .U32Str(maxQ) // maximum q
                .U32Str(masterSecret.Length) // length of master secret.
                .Bytes(masterSecret) // the master secret
                .Build();
        }
    }
}
