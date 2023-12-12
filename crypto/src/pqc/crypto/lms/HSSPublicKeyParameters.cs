using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssPublicKeyParameters
        : LmsKeyParameters, ILmsContextBasedVerifier
    {
        private readonly int m_level; // hierarchical level
        private readonly LmsPublicKeyParameters m_lmsPublicKey;

        public HssPublicKeyParameters(int l, LmsPublicKeyParameters lmsPublicKey)
    	    : base(false)
        {
            m_level = l;
            m_lmsPublicKey = lmsPublicKey ?? throw new ArgumentNullException(nameof(lmsPublicKey));
        }

        public static HssPublicKeyParameters GetInstance(object src)
        {
            if (src is HssPublicKeyParameters hssPublicKeyParameters)
                return hssPublicKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static HssPublicKeyParameters Parse(BinaryReader binaryReader)
        {
            int L = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LmsPublicKeyParameters lmsPublicKey = LmsPublicKeyParameters.Parse(binaryReader);
            return new HssPublicKeyParameters(L, lmsPublicKey);
        }

        [Obsolete("Use 'Level' instead")]
        public int L => m_level;

        public int Level => m_level;

        public LmsPublicKeyParameters LmsPublicKey => m_lmsPublicKey;

        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is HssPublicKeyParameters that
                && this.m_level == that.m_level
                && this.m_lmsPublicKey.Equals(that.m_lmsPublicKey);
        }

        public override int GetHashCode()
        {
            int result = m_level;
            result = 31 * result + m_lmsPublicKey.GetHashCode();
            return result;
        }

        public override byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(m_level)
                .Bytes(m_lmsPublicKey.GetEncoded())
                .Build();
        }

        public LmsContext GenerateLmsContext(byte[] sigEnc)
        {
            HssSignature signature;
            try
            {
                signature = HssSignature.GetInstance(sigEnc, Level);
            }
            catch (IOException e)
            {
                throw new Exception($"cannot parse signature: {e.Message}");
            }

            LmsSignedPubKey[] signedPubKeys = signature.SignedPubKeys;
            LmsPublicKeyParameters key = LmsPublicKey;
            if (signedPubKeys.Length != 0)
            {
                key = signedPubKeys[signedPubKeys.Length - 1].PublicKey;
            }

            return key.GenerateOtsContext(signature.Signature).WithSignedPublicKeys(signedPubKeys);
        }

        public bool Verify(LmsContext context)
        {
            LmsSignedPubKey[] sigKeys = context.SignedPubKeys;

            if (sigKeys.Length != Level - 1)
                return false;

            LmsPublicKeyParameters key = LmsPublicKey;
            bool failed = false;

            for (int i = 0; i < sigKeys.Length; i++)
            {
                LmsSignature sig = sigKeys[i].Signature;
                LmsPublicKeyParameters nextKey = sigKeys[i].PublicKey;

                if (!Lms.VerifySignature(key, sig, nextKey.ToByteArray()))
                {
                    failed = true;
                }

                key = nextKey;
            }

            return !failed & key.Verify(context);
        }
    }
}
