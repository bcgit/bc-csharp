using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    /// <summary>A Classic McEliece private (decapsulation) key, represented by its raw byte encoding.</summary>
    public sealed class CmcePrivateKeyParameters
        : CmceKeyParameters
    {
        internal readonly byte[] privateKey;

        /// <summary>Returns a copy of the raw private key bytes.</summary>
        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privateKey);
        }

        /// <summary>Creates a Classic McEliece private key from its raw encoding.</summary>
        /// <param name="parameters">The Classic McEliece parameter set this key belongs to.</param>
        /// <param name="privateKey">The raw private key bytes; a defensive copy is taken.</param>
        public CmcePrivateKeyParameters(CmceParameters parameters, byte[] privateKey)
            : base(true, parameters)
        {
            this.privateKey = Arrays.Clone(privateKey);
        }

        /// <summary>Creates a Classic McEliece private key from its component fields.</summary>
        /// <param name="parameters">The Classic McEliece parameter set this key belongs to.</param>
        /// <param name="delta">The delta component.</param>
        /// <param name="C">The C component.</param>
        /// <param name="g">The Goppa polynomial component.</param>
        /// <param name="alpha">The field-ordering component.</param>
        /// <param name="s">The s component.</param>
        public CmcePrivateKeyParameters(CmceParameters parameters, byte[] delta, byte[] C, byte[] g, byte[] alpha,
            byte[] s)
            : base(true, parameters)
        {
            int sk_size = delta.Length + C.Length + g.Length + alpha.Length + s.Length;
            privateKey = new byte[sk_size];
            int offset = 0;
            Array.Copy(delta, 0, privateKey, offset, delta.Length);
            offset += delta.Length;
            Array.Copy(C, 0, privateKey, offset, C.Length);
            offset += C.Length;
            Array.Copy(g, 0, privateKey, offset, g.Length);
            offset += g.Length;
            Array.Copy(alpha, 0, privateKey, offset, alpha.Length);
            offset += alpha.Length;
            Array.Copy(s, 0, privateKey, offset, s.Length);

        }

        /// <summary>Reconstructs the matching public key from this private key.</summary>
        public byte[] ReconstructPublicKey() => Parameters.Engine.GeneratePublicKeyFromPrivateKey(privateKey);

        /// <summary>Returns a copy of the raw private key encoding.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(privateKey);
        }

        internal byte[] Delta => Arrays.CopyOfRange(privateKey, 0, 32);

        internal byte[] C => Arrays.CopyOfRange(privateKey, 32, 32 + 8);

        internal byte[] G => Arrays.CopyOfRange(privateKey, 40, 40 + Parameters.T * 2);

        internal byte[] Alpha => Arrays.CopyOfRange(privateKey, 40 + Parameters.T * 2, privateKey.Length - 32);

        internal byte[] S => Arrays.CopyOfRange(privateKey, privateKey.Length - 32, privateKey.Length);
    }
}
