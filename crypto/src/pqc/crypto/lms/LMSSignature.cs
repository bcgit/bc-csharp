using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>An LMS signature.</summary>
    // TODO[api] Make internal
    public class LmsSignature
        : IEncodable
    {
        private readonly int m_q;
        private readonly LMOtsSignature m_otsSignature;
        private readonly LMSigParameters m_parameters;
        private readonly byte[][] m_y;

        /// <summary>Create a new <see cref="LmsSignature"/>.</summary>
        /// <param name="q">The q.</param>
        /// <param name="otsSignature">The ots signature.</param>
        /// <param name="parameter">The parameter.</param>
        /// <param name="y">The second operand.</param>
        public LmsSignature(int q, LMOtsSignature otsSignature, LMSigParameters parameter, byte[][] y)
        {
            m_q = q;
            m_otsSignature = otsSignature;
            m_parameters = parameter;
            m_y = y;
        }

        /// <summary>Return an <see cref="LmsSignature"/> from the given object.</summary>
        /// <param name="src">
        /// An <see cref="LmsSignature"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="LmsSignature"/>, or null if <paramref name="src"/> is null.</returns>
        public static LmsSignature GetInstance(object src)
        {
            if (src is LmsSignature lmsSignature)
                return lmsSignature;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, bytes, 0, bytes.Length, "LMS signature");

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsSignature Parse(BinaryReader binaryReader)
        {
            int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

            LMOtsSignature otsSignature = LMOtsSignature.Parse(binaryReader);

            LMSigParameters sigParameter = LMSigParameters.ParseByID(binaryReader);

            byte[][] path = new byte[sigParameter.H][];
            for (int h = 0; h < path.Length; h++)
            {
                path[h] = BinaryReaders.ReadBytesFully(binaryReader, sigParameter.M);
            }

            return new LmsSignature(q, otsSignature, sigParameter, path);
        }

        /// <inheritdoc/>
        // TODO[api] Fix parameter name
        public override bool Equals(object o)
        {
            if (this == o)
                return true;

            return o is LmsSignature that
                && this.m_q == that.m_q
                && Objects.Equals(this.m_otsSignature, that.m_otsSignature)
                && Objects.Equals(this.m_parameters, that.m_parameters)
                && DeepEquals(this.m_y, that.m_y);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            int result = m_q;
            result = 31 * result + Objects.GetHashCode(m_otsSignature);
            result = 31 * result + Objects.GetHashCode(m_parameters);
            result = 31 * result + DeepGetHashCode(m_y);
            return result;
        }

        /// <inheritdoc/>
        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(m_q)
                .Bytes(m_otsSignature.GetEncoded())
                .U32Str(m_parameters.ID)
                .Bytes2(m_y)
                .Build();
        }

        /// <summary>Gets the ots signature.</summary>
        public LMOtsSignature OtsSignature => m_otsSignature;

        /// <summary>Gets the q.</summary>
        public int Q => m_q;

        /// <summary>Gets the sig parameters.</summary>
        public LMSigParameters SigParameters => m_parameters;

        /// <summary>Gets the y.</summary>
        // TODO[api]
        public byte[][] Y => m_y;

        private static bool DeepEquals(byte[][] a, byte[][] b)
        {
            if (a == b)
                return true;

            int length = a.Length;
            if (length != b.Length)
                return false;

            for (int i = 0; i < length; ++i)
            {
                if (!Arrays.AreEqual(a[i], b[i]))
                    return false;
            }

            return true;
        }

        private static int DeepGetHashCode(byte[][] a)
        {
            if (a == null)
                return 0;

            int length = a.Length;
            int hc = length + 1;

            for (int i = 0; i < length; ++i)
            {
                hc *= 257;
                hc ^= Arrays.GetHashCode(a[i]);
            }

            return hc;
        }
    }
}
