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

        /// <summary>Create a new <see cref="HssPublicKeyParameters"/>.</summary>
        /// <param name="l">The l.</param>
        /// <param name="lmsPublicKey">The lms public key.</param>
        public HssPublicKeyParameters(int l, LmsPublicKeyParameters lmsPublicKey)
            : base(false)
        {
            m_level = l;
            m_lmsPublicKey = lmsPublicKey ?? throw new ArgumentNullException(nameof(lmsPublicKey));
        }

        /// <summary>Return an <see cref="HssPublicKeyParameters"/> from the given object.</summary>
        /// <param name="src">
        /// An <see cref="HssPublicKeyParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="HssPublicKeyParameters"/>, or null if <paramref name="src"/> is null.</returns>
        public static HssPublicKeyParameters GetInstance(object src)
        {
            if (src is HssPublicKeyParameters hssPublicKeyParameters)
                return hssPublicKeyParameters;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return Parse(stream);

            if (src is byte[] bytes)
                return Parse(bytes);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static HssPublicKeyParameters Parse(BinaryReader binaryReader)
        {
            int L = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (L < 1 || L > 8)    // RFC 8554, Section 6.
                throw new IOException($"L value of HSS public key out of range: {L}");

            LmsPublicKeyParameters lmsPublicKey = LmsPublicKeyParameters.Parse(binaryReader);
            return new HssPublicKeyParameters(L, lmsPublicKey);
        }

        internal static HssPublicKeyParameters Parse(Stream stream) =>
            BinaryReaders.Parse(Parse, stream, leaveOpen: true);

        internal static HssPublicKeyParameters Parse(byte[] buf) => Parse(buf, 0, buf.Length);

        internal static HssPublicKeyParameters Parse(byte[] buf, int off, int len) =>
            BinaryReaders.Parse(Parse, buf, off, len, "HSS public key");

        /// <summary>Gets the l.</summary>
        [Obsolete("Use 'Level' instead")]
        public int L => m_level;

        /// <summary>Gets the level.</summary>
        public int Level => m_level;

        public LmsPublicKeyParameters LmsPublicKey => m_lmsPublicKey;

        /// <inheritdoc/>
        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is HssPublicKeyParameters that
                && this.m_level == that.m_level
                && this.m_lmsPublicKey.Equals(that.m_lmsPublicKey);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            int result = m_level;
            result = 31 * result + m_lmsPublicKey.GetHashCode();
            return result;
        }

        /// <inheritdoc/>
        public override byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(m_level)
                .Bytes(m_lmsPublicKey.GetEncoded())
                .Build();
        }

        /// <inheritdoc/>
        public LmsContext GenerateLmsContext(byte[] sigEnc) =>
            GenerateLmsContext(HssSignature.GetInstance(sigEnc, Level));

        internal LmsContext GenerateLmsContext(HssSignature signature)
        {
            LmsSignedPubKey[] signedPubKeys = signature.SignedPubKeys;
            LmsPublicKeyParameters key = LmsPublicKey;
            if (signedPubKeys.Length != 0)
            {
                key = signedPubKeys[signedPubKeys.Length - 1].PublicKey;
            }

            return key.GenerateOtsContext(signature.Signature).WithSignedPublicKeys(signedPubKeys);
        }

        /// <inheritdoc/>
        public bool Verify(LmsContext context) => LmsEngine.VerifyHssSignature(this, context);
    }
}
