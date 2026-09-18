using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsPublicKeyParameters
        : LmsKeyParameters, ILmsContextBasedVerifier
    {
        private readonly LmsParameters m_lmsParameters;
        private byte[] I;
        private byte[] T1;

        // TODO[api] Rename parameters
        public LmsPublicKeyParameters(LMSigParameters parameterSet, LMOtsParameters lmOtsType, byte[] T1, byte[] I)
            : this(LmsParameters.Create(parameterSet, lmOtsType), Arrays.Clone(T1), Arrays.Clone(I))
        {
        }

        /// <remarks>Takes ownership of <paramref name="T1"/> and <paramref name="I"/> without copying.</remarks>
        internal LmsPublicKeyParameters(LmsParameters lmsParameters, byte[] T1, byte[] I)
            : base(false)
        {
            this.m_lmsParameters = lmsParameters;
            this.I = I;
            this.T1 = T1;
        }

        public LmsParameters LmsParameters => m_lmsParameters;

        public LMSigParameters SigParameters => m_lmsParameters.LMSigParameters;

        public LMOtsParameters OtsParameters => m_lmsParameters.LMOtsParameters;

        public static LmsPublicKeyParameters GetInstance(object src)
        {
            if (src is LmsPublicKeyParameters lmsPublicKeyParameters)
                return lmsPublicKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return Parse(stream);

            if (src is byte[] bytes)
                return Parse(bytes);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsPublicKeyParameters Parse(BinaryReader binaryReader)
        {
            LMSigParameters sigParameter = LMSigParameters.ParseByID(binaryReader);
            LMOtsParameters otsParameter = LMOtsParameters.ParseByID(binaryReader);

            byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

            byte[] T1 = BinaryReaders.ReadBytesFully(binaryReader, sigParameter.M);

            return new LmsPublicKeyParameters(LmsParameters.Create(sigParameter, otsParameter), T1, I);
        }

        internal static LmsPublicKeyParameters Parse(Stream stream) =>
            BinaryReaders.Parse(Parse, stream, leaveOpen: true);

        internal static LmsPublicKeyParameters Parse(byte[] buf) => Parse(buf, 0, buf.Length);

        internal static LmsPublicKeyParameters Parse(byte[] buf, int off, int len) =>
            BinaryReaders.Parse(Parse, buf, off, len, "LMS public key");

        public override byte[] GetEncoded() => ToByteArray();

        // TODO[api] Remove at promotion
        public LMSigParameters GetSigParameters() => SigParameters;

        // TODO[api] Remove at promotion
        public LMOtsParameters GetOtsParameters() => OtsParameters;

        // TODO[api] Remove at promotion
        public LmsParameters GetLmsParameters() => m_lmsParameters;

        public byte[] GetT1() => Arrays.Clone(T1);

        internal bool MatchesT1(byte[] sig) => Arrays.FixedTimeEquals(T1, sig);

        public byte[] GetI() => Arrays.Clone(I);

        internal byte[] InternalI => I;

        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is LmsPublicKeyParameters that
                && this.m_lmsParameters.Equals(that.m_lmsParameters)
                && Arrays.AreEqual(this.I, that.I)
                && Arrays.AreEqual(this.T1, that.T1);
        }

        public override int GetHashCode()
        {
            int result = m_lmsParameters.GetHashCode();
            result = 31 * result + Arrays.GetHashCode(I);
            result = 31 * result + Arrays.GetHashCode(T1);
            return result;
        }

        internal byte[] ToByteArray() => ComposeEncoding().Build();

        /// <summary>Feed the encoding to <paramref name="digest"/> without building it.</summary>
        internal void UpdateDigest(IDigest digest) => ComposeEncoding().BuildTo(digest);

        private Composer ComposeEncoding() =>
            Composer.Compose()
                .U32Str(SigParameters.ID)
                .U32Str(OtsParameters.ID)
                .Bytes(I)
                .Bytes(T1);

        public LmsContext GenerateLmsContext(byte[] signature) =>
            GenerateOtsContext(LmsSignature.GetInstance(signature));

        internal LmsContext GenerateOtsContext(LmsSignature signature)
        {
            // RFC 8554 sec. 5.4.2: the signature's LMS typecode must be the public key's (step 2g) and its leaf
            // number must lie within the tree (step 2i). Otherwise the verification takes h and the hash function
            // from the signature rather than the key, and node_num walks outside the tree; neither is a forgery
            // by itself, since T1 still has to match, but both are refused up front.
            if (signature.SigParameters.ID != SigParameters.ID)
                throw new ArgumentException("lms type from lms signature does not match the public key's lms type");
            if (signature.Q < 0 || signature.Q >= (1 << SigParameters.H))
                throw new ArgumentException("lms leaf number q from lms signature is outside the tree");

            int ots_typecode = GetOtsParameters().ID;
            if (signature.OtsSignature.ParamType.ID != ots_typecode)
            {
                throw new ArgumentException("ots type from lsm signature does not match ots" +
                    " signature type from embedded ots signature");
            }

            var otsParameters = LMOtsParameters.GetParametersByID(ots_typecode);
            var otsPublicKey = new LMOtsPublicKey(otsParameters, I, signature.Q, k: null);
            return otsPublicKey.CreateOtsContext(signature);
        }

        public bool Verify(LmsContext context) => LmsEngine.VerifySignature(this, context);
    }
}
