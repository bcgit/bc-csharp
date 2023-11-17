using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssSignature
        : IEncodable
    {
        private readonly int m_lMinus1;
        private readonly LmsSignedPubKey[] m_signedPubKey;
        private readonly LmsSignature m_signature;

        // TODO[api] signedPubKeys
        public HssSignature(int lMinus1, LmsSignedPubKey[] signedPubKey, LmsSignature signature)
        {
            m_lMinus1 = lMinus1;
            m_signedPubKey = signedPubKey;
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

        public int GetLMinus1()
        {
            return m_lMinus1;
        }

        // FIXME
        public LmsSignedPubKey[] GetSignedPubKeys()
        {
            return m_signedPubKey;
        }

        public LmsSignature Signature => m_signature;

        public override bool Equals(object other)
        {
            if (this == other)
                return true;
            if (!(other is HssSignature that))
                return false;

            if (this.m_lMinus1 != that.m_lMinus1)
                return false;

            if (this.m_signedPubKey.Length != that.m_signedPubKey.Length)
                return false;

            for (int t = 0; t < m_signedPubKey.Length; t++)
            {
                if (!this.m_signedPubKey[t].Equals(that.m_signedPubKey[t]))
                    return false;
            }

            return Equals(this.m_signature, that.m_signature);
        }

        public override int GetHashCode()
        {
            int result = m_lMinus1;
            result = 31 * result + m_signedPubKey.GetHashCode();
            result = 31 * result + (m_signature != null ? m_signature.GetHashCode() : 0);
            return result;
        }

        public byte[] GetEncoded()
        {
            Composer composer = Composer.Compose();
            composer.U32Str(m_lMinus1);
            if (m_signedPubKey != null)
            {
                foreach (LmsSignedPubKey sigPub in m_signedPubKey)
                {
                    composer.Bytes(sigPub);
                }
            }

            composer.Bytes(m_signature);
            return composer.Build();
        }
    }
}
