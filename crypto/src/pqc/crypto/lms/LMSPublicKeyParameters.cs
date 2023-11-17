using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsPublicKeyParameters
        : LmsKeyParameters, ILmsContextBasedVerifier
    {
        private LMSigParameters parameterSet;
        private LMOtsParameters lmOtsType;
        private byte[] I;
        private byte[] T1;

        public LmsPublicKeyParameters(LMSigParameters parameterSet, LMOtsParameters lmOtsType, byte[] T1, byte[] I)
            : base(false)
        {
            this.parameterSet = parameterSet;
            this.lmOtsType = lmOtsType;
            this.I = Arrays.Clone(I);
            this.T1 = Arrays.Clone(T1);
        }

        public static LmsPublicKeyParameters GetInstance(object src)
        {
            if (src is LmsPublicKeyParameters lmsPublicKeyParameters)
                return lmsPublicKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsPublicKeyParameters Parse(BinaryReader binaryReader)
        {
            int pubType = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LMSigParameters lmsParameter = LMSigParameters.GetParametersByID(pubType);

            int index = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LMOtsParameters ostTypeCode = LMOtsParameters.GetParametersByID(index);

            byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

            byte[] T1 = BinaryReaders.ReadBytesFully(binaryReader, lmsParameter.M);

            return new LmsPublicKeyParameters(lmsParameter, ostTypeCode, T1, I);
        }

        public override byte[] GetEncoded()
        {
            return this.ToByteArray();
        }

        public LMSigParameters GetSigParameters()
        {
            return parameterSet;
        }

        public LMOtsParameters GetOtsParameters()
        {
            return lmOtsType;
        }

        public LmsParameters GetLmsParameters()
        {
            return new LmsParameters(this.GetSigParameters(), this.GetOtsParameters());
        }

        public byte[] GetT1()
        {
            return Arrays.Clone(T1);
        }

        internal bool MatchesT1(byte[] sig)
        {
            return Arrays.FixedTimeEquals(T1, sig);
        }

        public byte[] GetI()
        {
            return Arrays.Clone(I);
        }

        byte[] RefI()
        {
            return I;
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

            LmsPublicKeyParameters publicKey = (LmsPublicKeyParameters)o;

            if (!parameterSet.Equals(publicKey.parameterSet))
            {
                return false;
            }
            if (!lmOtsType.Equals(publicKey.lmOtsType))
            {
                return false;
            }
            if (!Arrays.AreEqual(I, publicKey.I))
            {
                return false;
            }
            return Arrays.AreEqual(T1, publicKey.T1);
        }

        public override int GetHashCode()
        {
            int result = parameterSet.GetHashCode();
            result = 31 * result + lmOtsType.GetHashCode();
            result = 31 * result + Arrays.GetHashCode(I);
            result = 31 * result + Arrays.GetHashCode(T1);
            return result;
        }

        internal byte[] ToByteArray()
        {
            return Composer.Compose()
                .U32Str(parameterSet.ID)
                .U32Str(lmOtsType.ID)
                .Bytes(I)
                .Bytes(T1)
                .Build();
        }

        public LmsContext GenerateLmsContext(byte[] signature)
        {
            try
            {
                return GenerateOtsContext(LmsSignature.GetInstance(signature));
            }
            catch (IOException e)
            {
                throw new IOException($"cannot parse signature: {e.Message}");
            }
        }

        internal LmsContext GenerateOtsContext(LmsSignature S)
        {
            int ots_typecode = GetOtsParameters().ID;
            if (S.OtsSignature.ParamType.ID != ots_typecode)
            {
                throw new ArgumentException("ots type from lsm signature does not match ots" +
                    " signature type from embedded ots signature");
            }

            return new LMOtsPublicKey(LMOtsParameters.GetParametersByID(ots_typecode), I,  S.Q, null)
                .CreateOtsContext(S);
        }

        public bool Verify(LmsContext context)
        {
            return Lms.VerifySignature(this, context);
        }
    }
}
