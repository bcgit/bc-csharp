#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Reflection;
using System.Security.Cryptography;

using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Utilities
{
    /// <summary>
    /// Implements the <see href="https://lib25519.cr.yp.to">lib25519</see> API.
    /// </summary>
    /// <remarks>
    /// Full interoperability with <b>lib25519</b> keys, shared secrets, and (signed) messages. Note that <i>signing is not
    /// guaranteed to be deterministic</i>, so signing the same message under the same key may produce different signed
    /// messages each time.
    /// </remarks>
    public static class Lib25519
    {
        /// <summary>Equivalent of <c>lib25519_dh_BYTES</c>.</summary>
        public static readonly int DHBytes = X25519.PointSize;

        /// <summary>Equivalent of <c>lib25519_dh_PUBLICKEYBYTES</c>.</summary>
        public static readonly int DHPublicKeyBytes = X25519.PointSize;

        /// <summary>Equivalent of <c>lib25519_dh_SECRETKEYBYTES</c>.</summary>
        public static readonly int DHSecretKeyBytes = X25519.ScalarSize;

        /// <summary>Equivalent of <c>lib25519_sign_BYTES</c>.</summary>
        public static readonly int SignBytes = Ed25519.SignatureSize;

        /// <summary>Equivalent of <c>lib25519_sign_PUBLICKEYBYTES</c>.</summary>
        public static readonly int SignPublicKeyBytes = Ed25519.PublicKeySize;

        /// <summary>Equivalent of <c>lib25519_sign_SECRETKEYBYTES</c>.</summary>
        public static readonly int SignSecretKeyBytes = Ed25519.SecretKeySize + Ed25519.PublicKeySize;

        /// <summary>Equivalent of <c>lib25519_dh</c>.</summary>
        /// <remarks>
        /// Computes the X25519 secret <paramref name="k"/> shared between Alice and Bob, given Bob's public key
        /// <paramref name="pk"/> and Alice's secret key <paramref name="sk"/>.
        /// </remarks>
        /// <param name="k">
        /// A <c>Span</c> of length exactly <see cref="DHBytes"/> to receive the generated shared secret.
        /// </param>
        /// <param name="pk">
        /// A <c>ReadOnlySpan</c> of length exactly <see cref="DHPublicKeyBytes"/> containing Bob's public key.
        /// </param>
        /// <param name="sk">
        /// A <c>ReadOnlySpan</c> of length exactly <see cref="DHSecretKeyBytes"/> containing Alice's secret key.
        /// </param>
        /// <exception cref="ArgumentException">If any parameter has an invalid length.</exception>
        public static void DH(Span<byte> k, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sk)
        {
            if (sk.Length != DHSecretKeyBytes)
                throw new ArgumentException(nameof(sk));
            if (pk.Length != DHPublicKeyBytes)
                throw new ArgumentException(nameof(pk));
            if (k.Length != DHBytes)
                throw new ArgumentException(nameof(k));

            X25519.CalculateAgreement(sk, pk, k);
        }

        /// <summary>Equivalent of <c>lib25519_dh_keypair</c>.</summary>
        /// <remarks>
        /// Randomly generates Alice's secret key <paramref name="sk"/> and Alice's corresponding public key
        /// <paramref name="pk"/>.
        /// </remarks>
        /// <param name="pk">
        /// A <c>Span</c> of length exactly <see cref="DHPublicKeyBytes"/> to receive the generated public key.
        /// </param>
        /// <param name="sk">
        /// A <c>Span</c> of length exactly <see cref="DHSecretKeyBytes"/> to receive the generated secret key.
        /// </param>
        /// <exception cref="ArgumentException">If any parameter has an invalid length.</exception>
        public static void DHKeyPair(Span<byte> pk, Span<byte> sk)
        {
            if (sk.Length != DHSecretKeyBytes)
                throw new ArgumentException(nameof(sk));
            if (pk.Length != DHPublicKeyBytes)
                throw new ArgumentException(nameof(pk));

            RandomNumberGenerator.Fill(sk);
            X25519.GeneratePublicKey(sk, pk);
        }

        /// <summary>Equivalent of <c>lib25519_sign</c>.</summary>
        /// <remarks>
        /// Signs a message <paramref name="m"/> using the signer's secret key <paramref name="sk"/>, puts the length of
        /// the signed message into <paramref name="smlen"/>, and puts the signed message into
        /// <c><paramref name="sm"/>[..smlen]</c>.
        /// <para>
        /// The maximum possible length <paramref name="smlen"/> is <c>(<paramref name="m"/>.Length +
        /// <see cref="SignBytes"/>)</c>, so the caller must ensure <paramref name="sm"/> is at least that long.
        /// </para>
        /// </remarks>
        /// <param name="sm">
        /// A <c>Span</c> of length at least <c>(<paramref name="m"/>.Length + <see cref="SignBytes"/>)</c> to receive
        /// the signed message.
        /// </param>
        /// <param name="smlen">
        /// Receives the length of the signed message written to <paramref name="sm"/>.
        /// </param>
        /// <param name="m">
        /// A <c>ReadOnlySpan</c> containing the message to sign.
        /// </param>
        /// <param name="sk">
        /// A <c>ReadOnlySpan</c> of length exactly <see cref="SignSecretKeyBytes"/> containing the secret key.
        /// </param>
        /// <exception cref="ArgumentException">If any parameter has an invalid length.</exception>
        public static void Sign(Span<byte> sm, out int smlen, ReadOnlySpan<byte> m, ReadOnlySpan<byte> sk)
        {
            if (sk.Length != SignSecretKeyBytes)
                throw new ArgumentException(nameof(sk));

            int _mlen = m.Length;
            if (_mlen > int.MaxValue - SignBytes)
                throw new ArgumentException(nameof(m));

            int _smlen = _mlen + SignBytes;
            if (sm.Length < _smlen)
                throw new ArgumentException(nameof(sm));

            var _sk = sk[..Ed25519.SecretKeySize];
            var _pk = sk[Ed25519.SecretKeySize..];

            var sig = sm.Slice(0, SignBytes);
            var msg = sm.Slice(SignBytes, _mlen);

            m.CopyTo(msg);
            Ed25519.Sign(_sk, _pk, msg, sig);
            smlen = _smlen;
        }

        /// <summary>Equivalent of <c>lib25519_sign_keypair</c>.</summary>
        /// <remarks>
        /// Randomly generates a secret key <paramref name="sk"/> and a corresponding public key <paramref name="pk"/>.
        /// </remarks>
        /// <param name="pk">
        /// A <c>Span</c> of length exactly <see cref="SignPublicKeyBytes"/> to receive the generated public key.
        /// </param>
        /// <param name="sk">
        /// A <c>Span</c> of length exactly <see cref="SignSecretKeyBytes"/> to receive the generated secret key.
        /// </param>
        /// <exception cref="ArgumentException">If any parameter has an invalid length.</exception>
        public static void SignKeyPair(Span<byte> pk, Span<byte> sk)
        {
            if (sk.Length != SignSecretKeyBytes)
                throw new ArgumentException(nameof(sk));
            if (pk.Length != SignPublicKeyBytes)
                throw new ArgumentException(nameof(pk));

            var _sk = sk[..Ed25519.SecretKeySize];
            var _pk = sk[Ed25519.SecretKeySize..];

            RandomNumberGenerator.Fill(_sk);
            Ed25519.GeneratePublicKey(_sk, pk);
            pk.CopyTo(_pk);
        }

        /// <summary>Equivalent of <c>lib25519_sign_open</c>.</summary>
        /// <remarks>
        /// Verifies the signed message in <paramref name="sm"/> using the signer's public key <paramref name="pk"/>.
        /// This function puts the length of the message into <paramref name="mlen"/> and puts the message into
        /// <c><paramref name="m"/>[..mlen]</c>. It then returns <c>true</c>.
        /// <para>
        /// The maximum possible length <paramref name="mlen"/> is <c><paramref name="sm"/>.Length</c>, so the caller must
        /// ensure <paramref name="m"/> is at least that long.
        /// </para>
        /// <para>
        /// If the signature fails verification, this method instead returns <c>false</c>. It also sets
        /// <paramref name="mlen"/> to <c>-1</c> and clears <c><paramref name="m"/>[..<paramref name="sm"/>.Length]</c>,
        /// but callers should note that other signature software does not necessarily do this; callers should always
        /// check the return value.
        /// </para>
        /// </remarks>
        /// <param name="m">
        /// A <c>Span</c> of length at least <c><paramref name="sm"/>.Length</c> to receive the signed message.
        /// </param>
        /// <param name="mlen">
        /// Receives the length of the message written to <paramref name="m"/>.
        /// </param>
        /// <param name="sm">
        /// A <c>ReadOnlySpan</c> containing the signed message to open.
        /// </param>
        /// <param name="pk">
        /// A <c>ReadOnlySpan</c> of length exactly <see cref="SignPublicKeyBytes"/> containing the public key.
        /// </param>
        /// <returns>
        /// <c>true</c> if verification succeeded, or <c>false</c> if verification failed.
        /// </returns>
        /// <exception cref="ArgumentException">If any parameter has an invalid length.</exception>
        public static bool SignOpen(Span<byte> m, out int mlen, ReadOnlySpan<byte> sm, ReadOnlySpan<byte> pk)
        {
            if (pk.Length != SignPublicKeyBytes)
                throw new ArgumentException(nameof(pk));

            int _smlen = sm.Length;
            if (_smlen < SignBytes)
                throw new ArgumentException(nameof(sm));

            int _mlen = _smlen - SignBytes;
            if (m.Length < _smlen)
                throw new ArgumentException(nameof(m));

            var sig = sm.Slice(0, SignBytes);
            var msg = sm.Slice(SignBytes, _mlen);

            if (!Ed25519.Verify(sig, pk, msg))
            {
                m[.._smlen].Fill(0x00);
                mlen = -1;
                return false;
            }

            msg.CopyTo(m);
            mlen = _mlen;
            return true;
        }
    }
}
#endif
