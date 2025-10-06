using System;

using Org.BouncyCastle.Tls.Crypto;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public abstract class SignatureScheme
    {
        /*
         * RFC 8446
         */

        public const int rsa_pkcs1_sha1 = 0x0201;
        public const int ecdsa_sha1 = 0x0203;

        public const int rsa_pkcs1_sha256 = 0x0401;
        public const int rsa_pkcs1_sha384 = 0x0501;
        public const int rsa_pkcs1_sha512 = 0x0601;

        public const int ecdsa_secp256r1_sha256 = 0x0403;
        public const int ecdsa_secp384r1_sha384 = 0x0503;
        public const int ecdsa_secp521r1_sha512 = 0x0603;

        public const int rsa_pss_rsae_sha256 = 0x0804;
        public const int rsa_pss_rsae_sha384 = 0x0805;
        public const int rsa_pss_rsae_sha512 = 0x0806;

        public const int ed25519 = 0x0807;
        public const int ed448 = 0x0808;

        public const int rsa_pss_pss_sha256 = 0x0809;
        public const int rsa_pss_pss_sha384 = 0x080A;
        public const int rsa_pss_pss_sha512 = 0x080B;

        /*
         * RFC 8734
         */

        public const int ecdsa_brainpoolP256r1tls13_sha256 = 0x081A;
        public const int ecdsa_brainpoolP384r1tls13_sha384 = 0x081B;
        public const int ecdsa_brainpoolP512r1tls13_sha512 = 0x081C;

        /*
         * RFC 8998
         */

        public const int sm2sig_sm3 = 0x0708;

        /*
         * draft-ietf-tls-mldsa-00
         */
        public const int mldsa44 = 0x0904;
        public const int mldsa65 = 0x0905;
        public const int mldsa87 = 0x0906;

        [Obsolete("Use 'mldsa44' instead")]
        public static readonly int DRAFT_mldsa44 = mldsa44;
        [Obsolete("Use 'mldsa65' instead")]
        public static readonly int DRAFT_mldsa65 = mldsa65;
        [Obsolete("Use 'mldsa87' instead")]
        public static readonly int DRAFT_mldsa87 = mldsa87;

        /*
         * draft-reddy-tls-slhdsa-01
         */
        internal const int slhdsa_sha2_128s = 0x0911;
        internal const int slhdsa_sha2_128f = 0x0912;
        internal const int slhdsa_sha2_192s = 0x0913;
        internal const int slhdsa_sha2_192f = 0x0914;
        internal const int slhdsa_sha2_256s = 0x0915;
        internal const int slhdsa_sha2_256f = 0x0916;
        internal const int slhdsa_shake_128s = 0x0917;
        internal const int slhdsa_shake_128f = 0x0918;
        internal const int slhdsa_shake_192s = 0x0919;
        internal const int slhdsa_shake_192f = 0x091A;
        internal const int slhdsa_shake_256s = 0x091B;
        internal const int slhdsa_shake_256f = 0x091C;

        public static readonly int DRAFT_slhdsa_sha2_128s = slhdsa_sha2_128s;
        public static readonly int DRAFT_slhdsa_sha2_128f = slhdsa_sha2_128f;
        public static readonly int DRAFT_slhdsa_sha2_192s = slhdsa_sha2_192s;
        public static readonly int DRAFT_slhdsa_sha2_192f = slhdsa_sha2_192f;
        public static readonly int DRAFT_slhdsa_sha2_256s = slhdsa_sha2_256s;
        public static readonly int DRAFT_slhdsa_sha2_256f = slhdsa_sha2_256f;
        public static readonly int DRAFT_slhdsa_shake_128s = slhdsa_shake_128s;
        public static readonly int DRAFT_slhdsa_shake_128f = slhdsa_shake_128f;
        public static readonly int DRAFT_slhdsa_shake_192s = slhdsa_shake_192s;
        public static readonly int DRAFT_slhdsa_shake_192f = slhdsa_shake_192f;
        public static readonly int DRAFT_slhdsa_shake_256s = slhdsa_shake_256s;
        public static readonly int DRAFT_slhdsa_shake_256f = slhdsa_shake_256f;

        /*
         * RFC 8446 reserved for private use (0xFE00..0xFFFF)
         */

        public static int From(SignatureAndHashAlgorithm sigAndHashAlg)
        {
            if (null == sigAndHashAlg)
                throw new ArgumentNullException();

            return From(sigAndHashAlg.Hash, sigAndHashAlg.Signature);
        }

        public static int From(short hashAlgorithm, short signatureAlgorithm)
        {
            return ((hashAlgorithm & 0xFF) << 8) | (signatureAlgorithm & 0xFF);
        }

        public static int GetCryptoHashAlgorithm(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case ed25519:
            case ed448:
            case mldsa44:
            case mldsa65:
            case mldsa87:
            case slhdsa_sha2_128s:
            case slhdsa_sha2_128f:
            case slhdsa_sha2_192s:
            case slhdsa_sha2_192f:
            case slhdsa_sha2_256s:
            case slhdsa_sha2_256f:
            case slhdsa_shake_128s:
            case slhdsa_shake_128f:
            case slhdsa_shake_192s:
            case slhdsa_shake_192f:
            case slhdsa_shake_256s:
            case slhdsa_shake_256f:
                return -1;
            case ecdsa_brainpoolP256r1tls13_sha256:
            case rsa_pss_pss_sha256:
            case rsa_pss_rsae_sha256:
                return CryptoHashAlgorithm.sha256;
            case ecdsa_brainpoolP384r1tls13_sha384:
            case rsa_pss_pss_sha384:
            case rsa_pss_rsae_sha384:
                return CryptoHashAlgorithm.sha384;
            case ecdsa_brainpoolP512r1tls13_sha512:
            case rsa_pss_pss_sha512:
            case rsa_pss_rsae_sha512:
                return CryptoHashAlgorithm.sha512;
            case sm2sig_sm3:
                return CryptoHashAlgorithm.sm3;
            default:
            {
                short hashAlgorithm = GetHashAlgorithm(signatureScheme);
                if (HashAlgorithm.Intrinsic == hashAlgorithm || !HashAlgorithm.IsRecognized(hashAlgorithm))
                    return -1;

                return TlsCryptoUtilities.GetHash(hashAlgorithm);
            }
            }
        }

        public static int GetCryptoHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            return GetCryptoHashAlgorithm(From(signatureAndHashAlgorithm));
        }

        public static string GetName(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case rsa_pkcs1_sha1:
                return "rsa_pkcs1_sha1";
            case ecdsa_sha1:
                return "ecdsa_sha1";
            case rsa_pkcs1_sha256:
                return "rsa_pkcs1_sha256";
            case rsa_pkcs1_sha384:
                return "rsa_pkcs1_sha384";
            case rsa_pkcs1_sha512:
                return "rsa_pkcs1_sha512";
            case ecdsa_secp256r1_sha256:
                return "ecdsa_secp256r1_sha256";
            case ecdsa_secp384r1_sha384:
                return "ecdsa_secp384r1_sha384";
            case ecdsa_secp521r1_sha512:
                return "ecdsa_secp521r1_sha512";
            case rsa_pss_rsae_sha256:
                return "rsa_pss_rsae_sha256";
            case rsa_pss_rsae_sha384:
                return "rsa_pss_rsae_sha384";
            case rsa_pss_rsae_sha512:
                return "rsa_pss_rsae_sha512";
            case ed25519:
                return "ed25519";
            case ed448:
                return "ed448";
            case rsa_pss_pss_sha256:
                return "rsa_pss_pss_sha256";
            case rsa_pss_pss_sha384:
                return "rsa_pss_pss_sha384";
            case rsa_pss_pss_sha512:
                return "rsa_pss_pss_sha512";
            case ecdsa_brainpoolP256r1tls13_sha256:
                return "ecdsa_brainpoolP256r1tls13_sha256";
            case ecdsa_brainpoolP384r1tls13_sha384:
                return "ecdsa_brainpoolP384r1tls13_sha384";
            case ecdsa_brainpoolP512r1tls13_sha512:
                return "ecdsa_brainpoolP512r1tls13_sha512";
            case sm2sig_sm3:
                return "sm2sig_sm3";
            case mldsa44:
                return "mldsa44";
            case mldsa65:
                return "mldsa65";
            case mldsa87:
                return "mldsa87";
            case slhdsa_sha2_128s:
                return "slhdsa_sha2_128s";
            case slhdsa_sha2_128f:
                return "slhdsa_sha2_128f";
            case slhdsa_sha2_192s:
                return "slhdsa_sha2_192s";
            case slhdsa_sha2_192f:
                return "slhdsa_sha2_192f";
            case slhdsa_sha2_256s:
                return "slhdsa_sha2_256s";
            case slhdsa_sha2_256f:
                return "slhdsa_sha2_256f";
            case slhdsa_shake_128s:
                return "slhdsa_shake_128s";
            case slhdsa_shake_128f:
                return "slhdsa_shake_128f";
            case slhdsa_shake_192s:
                return "slhdsa_shake_192s";
            case slhdsa_shake_192f:
                return "slhdsa_shake_192f";
            case slhdsa_shake_256s:
                return "slhdsa_shake_256s";
            case slhdsa_shake_256f:
                return "slhdsa_shake_256f";
            default:
                return "UNKNOWN";
            }
        }

        /**
         * For TLS 1.3+ usage, some signature schemes are constrained to use a particular
         * ({@link NamedGroup}. Not relevant for TLS 1.2 and below.
         */
        public static int GetNamedGroup(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case ecdsa_brainpoolP256r1tls13_sha256:
                return NamedGroup.brainpoolP256r1tls13;
            case ecdsa_brainpoolP384r1tls13_sha384:
                return NamedGroup.brainpoolP384r1tls13;
            case ecdsa_brainpoolP512r1tls13_sha512:
                return NamedGroup.brainpoolP512r1tls13;
            case ecdsa_secp256r1_sha256:
                return NamedGroup.secp256r1;
            case ecdsa_secp384r1_sha384:
                return NamedGroup.secp384r1;
            case ecdsa_secp521r1_sha512:
                return NamedGroup.secp521r1;
            case sm2sig_sm3:
                return NamedGroup.curveSM2;
            default:
                return -1;
            }
        }

        public static short GetHashAlgorithm(int signatureScheme)
        {
            // TODO[RFC 8998] sm2sig_sm3
            return (short)((signatureScheme >> 8) & 0xFF);
        }

        public static short GetSignatureAlgorithm(int signatureScheme)
        {
            // TODO[RFC 8998] sm2sig_sm3
            return (short)(signatureScheme & 0xFF);
        }

        public static SignatureAndHashAlgorithm GetSignatureAndHashAlgorithm(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case ed25519:
                return SignatureAndHashAlgorithm.ed25519;
            case ed448:
                return SignatureAndHashAlgorithm.ed448;
            case mldsa44:
                return SignatureAndHashAlgorithm.mldsa44;
            case mldsa65:
                return SignatureAndHashAlgorithm.mldsa65;
            case mldsa87:
                return SignatureAndHashAlgorithm.mldsa87;
            case slhdsa_sha2_128s:
                return SignatureAndHashAlgorithm.slhdsa_sha2_128s;
            case slhdsa_sha2_128f:
                return SignatureAndHashAlgorithm.slhdsa_sha2_128f;
            case slhdsa_sha2_192s:
                return SignatureAndHashAlgorithm.slhdsa_sha2_192s;
            case slhdsa_sha2_192f:
                return SignatureAndHashAlgorithm.slhdsa_sha2_192f;
            case slhdsa_sha2_256s:
                return SignatureAndHashAlgorithm.slhdsa_sha2_256s;
            case slhdsa_sha2_256f:
                return SignatureAndHashAlgorithm.slhdsa_sha2_256f;
            case slhdsa_shake_128s:
                return SignatureAndHashAlgorithm.slhdsa_shake_128s;
            case slhdsa_shake_128f:
                return SignatureAndHashAlgorithm.slhdsa_shake_128f;
            case slhdsa_shake_192s:
                return SignatureAndHashAlgorithm.slhdsa_shake_192s;
            case slhdsa_shake_192f:
                return SignatureAndHashAlgorithm.slhdsa_shake_192f;
            case slhdsa_shake_256s:
                return SignatureAndHashAlgorithm.slhdsa_shake_256s;
            case slhdsa_shake_256f:
                return SignatureAndHashAlgorithm.slhdsa_shake_256f;
            default:
                return SignatureAndHashAlgorithm.GetInstance(
                    GetHashAlgorithm(signatureScheme),
                    GetSignatureAlgorithm(signatureScheme));
            }
        }

        public static string GetText(int signatureScheme)
        {
            string hex = Convert.ToString(signatureScheme, 16).ToUpperInvariant();
            return GetName(signatureScheme) + "(0x" + hex + ")";
        }

        public static bool IsPrivate(int signatureScheme)
        {
            return (signatureScheme >> 9) == 0xFE;
        }

        public static bool IsECDsa(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case ecdsa_brainpoolP256r1tls13_sha256:
            case ecdsa_brainpoolP384r1tls13_sha384:
            case ecdsa_brainpoolP512r1tls13_sha512:
                return true;
            default:
                return SignatureAlgorithm.ecdsa == GetSignatureAlgorithm(signatureScheme);
            }
        }

        [Obsolete("Use 'IsMLDsaScheme' instead")]
        public static bool isMLDsa(int signatureScheme) => IsMLDsaScheme(signatureScheme);

        public static bool IsMLDsaScheme(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case mldsa44:
            case mldsa65:
            case mldsa87:
                return true;
            default:
                return false;
            }
        }

        public static bool IsRsaPss(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case rsa_pss_rsae_sha256:
            case rsa_pss_rsae_sha384:
            case rsa_pss_rsae_sha512:
            case rsa_pss_pss_sha256:
            case rsa_pss_pss_sha384:
            case rsa_pss_pss_sha512:
                return true;
            default:
                return false;
            }
        }

        public static bool IsSlhDsa(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case slhdsa_sha2_128s:
            case slhdsa_sha2_128f:
            case slhdsa_sha2_192s:
            case slhdsa_sha2_192f:
            case slhdsa_sha2_256s:
            case slhdsa_sha2_256f:
            case slhdsa_shake_128s:
            case slhdsa_shake_128f:
            case slhdsa_shake_192s:
            case slhdsa_shake_192f:
            case slhdsa_shake_256s:
            case slhdsa_shake_256f:
                return true;
            default:
                return false;
            }
        }
    }
}
