using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public sealed class HssSignature
        : IEncodable
    {
        private readonly int m_lMinus1;
        private readonly LmsSignedPubKey[] m_signedPubKeys;
        private readonly LmsSignature m_signature;

        // TODO[api] signedPubKeys
        public HssSignature(int lMinus1, LmsSignedPubKey[] signedPubKey, LmsSignature signature)
        {
            m_lMinus1 = lMinus1;
            m_signedPubKeys = signedPubKey;
            m_signature = signature;
        }

        /**
         * @param src byte[], InputStream or HSSSignature
         * @param L   The HSS depth, available from public key.
         * @return An HSSSignature instance.
         * @throws IOException
         */
        public static HssSignature GetInstance(object src, int L)
        {
            if (src is HssSignature hssSignature)
                return hssSignature;

            if (src is BinaryReader binaryReader)
                return Parse(L, binaryReader);

            if (src is Stream stream)
                return Parse(L, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return Parse(L, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static HssSignature Parse(int L, BinaryReader binaryReader)
        {
            int lMinus1 = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (lMinus1 != L - 1)
                throw new Exception("nspk exceeded maxNspk");

            var signedPubKeys = new LmsSignedPubKey[lMinus1];
            for (int t = 0; t < lMinus1; t++)
            {
                var signature = LmsSignature.Parse(binaryReader);
                var publicKey = LmsPublicKeyParameters.Parse(binaryReader);

                signedPubKeys[t] = new LmsSignedPubKey(signature, publicKey);
            }

            {
                var signature = LmsSignature.Parse(binaryReader);

                return new HssSignature(lMinus1, signedPubKeys, signature);
            }
        }

        private static HssSignature Parse(int L, Stream stream, bool leaveOpen)
        {
            using (var binaryReader = new BinaryReader(stream, Encoding.UTF8, leaveOpen))
            {
                return Parse(L, binaryReader);
            }
        }

        [Obsolete("Use 'LMinus1' instead")]
        public int GetLMinus1()
        {
            return m_lMinus1;
        }

        public int LMinus1 => m_lMinus1;

        public LmsSignedPubKey[] GetSignedPubKeys() => (LmsSignedPubKey[])m_signedPubKeys?.Clone();

        internal LmsSignedPubKey[] SignedPubKeys => m_signedPubKeys;

        public LmsSignature Signature => m_signature;

        // TODO[api] Fix parameter name
        public override bool Equals(object other)
        {
            if (this == other)
                return true;

            return other is HssSignature that
                && this.m_lMinus1 == that.m_lMinus1
                && Arrays.AreEqual(this.m_signedPubKeys, that.m_signedPubKeys)
                && Objects.Equals(this.m_signature, that.m_signature);
        }

        public override int GetHashCode()
        {
            int result = m_lMinus1;
            result = 31 * result + Arrays.GetHashCode(m_signedPubKeys);
            result = 31 * result + Objects.GetHashCode(m_signature);
            return result;
        }

        public byte[] GetEncoded()
        {
            Composer composer = Composer.Compose();
            composer.U32Str(m_lMinus1);
            if (m_signedPubKeys != null)
            {
                foreach (LmsSignedPubKey sigPub in m_signedPubKeys)
                {
                    composer.Bytes(sigPub);
                }
            }

            composer.Bytes(m_signature);
            return composer.Build();
        }
    }
}
