using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconPrivateKeyParameters
        : FalconKeyParameters
    {
        private readonly byte[] m_pk;
        private readonly byte[] m_f;
        private readonly byte[] m_g;
        private readonly byte[] m_F;

        public FalconPrivateKeyParameters(FalconParameters parameters, byte[] f, byte[] g, byte[] F, byte[] pk_encoded)
            : base(true, parameters)
        {
            m_f = Arrays.CopyBuffer(f);
            m_g = Arrays.CopyBuffer(g);
            m_F = Arrays.CopyBuffer(F);
            m_pk = Arrays.CopyBuffer(pk_encoded);
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_f, m_g, m_F);

        public byte[] GetPublicKey() =>
            Arrays.IsNullOrEmpty(m_pk) ? DerivePublicKey() : Arrays.InternalCopyBuffer(m_pk);

        /// <summary>Return the matching public key parameters.</summary>
        public FalconPublicKeyParameters GetPublicKeyParameters() =>
            new FalconPublicKeyParameters(Parameters, GetPublicKey());

        public byte[] GetSpolyLittleF() => Arrays.InternalCopyBuffer(m_f);

        public byte[] GetG() => Arrays.InternalCopyBuffer(m_g);

        public byte[] GetSpolyBigF() => Arrays.InternalCopyBuffer(m_F);

        /// <summary>
        /// Recompute the encoded public key (h = g * f ^ -1 mod (q, x^n+1)) from the private polynomials, for the case
        /// where no encoded public key was retained.
        /// </summary>
        /// <remarks>
        /// The returned bytes match <see cref="GetPublicKey"/> of a freshly generated key.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        /// If the private polynomials cannot be decoded or f is not invertible mod q.
        /// </exception>
        private byte[] DerivePublicKey()
        {
            uint logn = Parameters.logn;
            int n = 1 << (int)logn;
            byte bits = FalconCodec.max_fg_bits[logn];

            sbyte[] fc = new sbyte[n];
            sbyte[] gc = new sbyte[n];

            if (FalconCodec.trim_i8_decode(fc, 0, logn, bits, m_f, 0, m_f.Length) == 0)
                throw new InvalidOperationException("unable to decode f");

            if (FalconCodec.trim_i8_decode(gc, 0, logn, bits, m_g, 0, m_g.Length) == 0)
                throw new InvalidOperationException("unable to decode g");

            ushort[] h = new ushort[n];
            ushort[] tmp = new ushort[n];
            if (FalconVrfy.compute_public(h, 0, fc, 0, gc, 0, logn, tmp, 0) == 0)
                throw new InvalidOperationException("unable to recover public key: f not invertible mod q");

            byte[] enc = new byte[1 + (14 * n / 8)];
            if (FalconCodec.modq_encode(enc, 1, enc.Length - 1, h, 0, logn) != enc.Length - 1)
                throw new InvalidOperationException("public key encoding failed");

            return Arrays.CopyOfRange(enc, 1, enc.Length);
        }
    }
}
