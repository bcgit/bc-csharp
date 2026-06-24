using System;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>An NTRU public (encapsulation) key, represented by its raw byte encoding.</summary>
    /// <remarks>Instances are immutable. Create them via <see cref="FromEncoding(NtruParameters, byte[])"/>.</remarks>
    public sealed class NtruPublicKeyParameters
        : NtruKeyParameters
    {
        /// <summary>Creates an <see cref="NtruPublicKeyParameters"/> from its raw public key encoding.</summary>
        /// <param name="parameters">The NTRU parameter set this key belongs to.</param>
        /// <param name="encoding">
        /// The raw public key bytes; length must equal the parameter set's public key length.
        /// </param>
        /// <returns>A new instance wrapping a defensive copy of <paramref name="encoding"/>.</returns>
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="parameters"/> or <paramref name="encoding"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> has the wrong length.</exception>
        public static NtruPublicKeyParameters FromEncoding(NtruParameters parameters, byte[] encoding)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NtruPublicKeyParameters(parameters, encoding);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly byte[] m_publicKey;

        [Obsolete("Use 'FromEncoding' instead")]
        public NtruPublicKeyParameters(NtruParameters parameters, byte[] key)
            : base(privateKey: false, parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != parameters.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(key));

            m_publicKey = (byte[])key.Clone();
        }

        /// <summary>Returns a copy of the raw public key encoding.</summary>
        public override byte[] GetEncoded() => (byte[])m_publicKey.Clone();

        /// <summary>Obsolete. Use <see cref="GetEncoded"/> instead.</summary>
        [Obsolete("Use 'GetEncoded' instead")]
        public byte[] PublicKey
        {
            get => GetEncoded();
            set => throw new NotSupportedException();
        }
    }
}
