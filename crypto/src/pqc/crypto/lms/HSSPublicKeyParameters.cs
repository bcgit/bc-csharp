using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssPublicKeyParameters
        : LmsKeyParameters, ILmsContextBasedVerifier
    {
        private readonly int m_l;
        private readonly LmsPublicKeyParameters m_lmsPublicKey;

        public HssPublicKeyParameters(int l, LmsPublicKeyParameters lmsPublicKey)
    	    :base(false)
        {
            m_l = l;
            m_lmsPublicKey = lmsPublicKey;
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

        public int L => m_l;

        public LmsPublicKeyParameters LmsPublicKey => m_lmsPublicKey;

        public override bool Equals(Object o)
        {
            if (this == o)
                return true;
            if (o == null || GetType() != o.GetType())
                return false;

            HssPublicKeyParameters publicKey = (HssPublicKeyParameters)o;

            return m_l == publicKey.m_l
                && m_lmsPublicKey.Equals(publicKey.m_lmsPublicKey);
        }

        public override int GetHashCode()
        {
            int result = m_l;
            result = 31 * result + m_lmsPublicKey.GetHashCode();
            return result;
        }

        public override byte[] GetEncoded()
        {
            return Composer.Compose().U32Str(m_l)
                .Bytes(m_lmsPublicKey.GetEncoded())
                .Build();
        }

        public LmsContext GenerateLmsContext(byte[] sigEnc)
        {
            HssSignature signature;
            try
            {
                signature = HssSignature.GetInstance(sigEnc, L);
            }
            catch (IOException e)
            {
                throw new Exception($"cannot parse signature: {e.Message}");
            }

            LmsSignedPubKey[] signedPubKeys = signature.GetSignedPubKeys();
            LmsPublicKeyParameters key = LmsPublicKey;
            if (signedPubKeys.Length != 0)
            {
                key = signedPubKeys[signedPubKeys.Length - 1].GetPublicKey();
            }

            return key.GenerateOtsContext(signature.Signature).WithSignedPublicKeys(signedPubKeys);
        }

        public bool Verify(LmsContext context)
        {
            LmsSignedPubKey[] sigKeys = context.SignedPubKeys;

            if (sigKeys.Length != L - 1)
                return false;

            LmsPublicKeyParameters key = LmsPublicKey;
            bool failed = false;

            for (int i = 0; i < sigKeys.Length; i++)
            {
                LmsSignature sig = sigKeys[i].GetSignature();
                byte[] msg = sigKeys[i].GetPublicKey().ToByteArray();
                if (!Lms.VerifySignature(key, sig, msg))
                {
                    failed = true;
                }
                key = sigKeys[i].GetPublicKey();
            }

            return !failed & key.Verify(context);
        }
    }
}