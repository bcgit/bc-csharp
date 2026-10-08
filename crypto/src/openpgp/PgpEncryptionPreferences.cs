using System;
using System.Collections.Generic;
using System.Linq;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// The choice of the message format and of the algorithms for a message to a set of recipients, from the
    /// preferences in their certificates (RFC 9580 9.2, 9.5, 10.1; RFC 9980 7.1, 9.5).
    /// </summary>
    /// <remarks>
    /// The preferences of a certificate are taken from its newest self-signature that verifies: for version 6
    /// certificates the direct-key signature, for version 4 certificates the certification of the primary user ID or,
    /// if there is none, a direct-key signature. Only the newest valid self-signature of each user ID counts, and a
    /// revocation removes the user ID. A version 4 certificate without such a signature has no explicit preferences;
    /// a version 6 certificate without a valid direct-key signature, or with a revoked primary key, cannot be used
    /// (RFC 9580 5.2.3.10).
    /// A version 6 certificate whose self-signature has no Features subpacket supports version 2 SEIPD. The result
    /// never names an algorithm that is not in the list of every recipient (the implicit algorithms included), and
    /// recipients with X25519, X448 or ML-KEM keys only get AES in version 1 SEIPD messages. Only the primary key and
    /// the subkeys with a binding signature that verifies make a certificate post-quantum (RFC 9980 7.1).
    /// </remarks>
    public sealed class PgpEncryptionPreferences
    {
        private static readonly PreferredAeadCiphersuites.Combination Aes256Ocb =
            new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb);

        private static readonly PreferredAeadCiphersuites.Combination Aes128Ocb =
            new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb);

        /// <summary>The preferences of one certificate, with the implicit algorithms added.</summary>
        private sealed class Preferences
        {
            internal readonly List<SymmetricKeyAlgorithmTag> Symmetric = new List<SymmetricKeyAlgorithmTag>();
            internal readonly List<PreferredAeadCiphersuites.Combination> Aead =
                new List<PreferredAeadCiphersuites.Combination>();
            internal bool SupportsSeipdV2;
            internal bool RequiresAes;
        }

        /// <summary>
        /// Choose the format and the algorithms for a message to the given certificates.
        /// </summary>
        /// <param name="recipientCertificates">The certificates of the recipients; at least one.</param>
        /// <exception cref="ArgumentException">
        /// If there is no certificate, or a version 6 certificate without a valid direct-key signature or with a
        /// revoked primary key.
        /// </exception>
        public static PgpEncryptionPreferences Select(IEnumerable<PgpPublicKeyRing> recipientCertificates)
        {
            if (recipientCertificates == null)
                throw new ArgumentNullException(nameof(recipientCertificates));

            List<Preferences> preferences = recipientCertificates.Select(GetPreferences).ToList();
            if (preferences.Count == 0)
                throw new ArgumentException("at least one certificate is needed", nameof(recipientCertificates));

            if (preferences.All(p => p.SupportsSeipdV2))
            {
                PreferredAeadCiphersuites.Combination combination = SelectCiphersuite(preferences);
                return new PgpEncryptionPreferences(true, combination.SymmetricAlgorithm,
                    combination.AeadAlgorithm);
            }

            return new PgpEncryptionPreferences(false, SelectCipher(preferences), AeadAlgorithmTag.Ocb);
        }

        private static PreferredAeadCiphersuites.Combination SelectCiphersuite(List<Preferences> preferences)
        {
            bool IsCommon(PreferredAeadCiphersuites.Combination c) => preferences.All(p => p.Aead.Contains(c));

            // RFC 9980 9.5: AES-256 if every recipient supports it, in the order of the first recipient
            PreferredAeadCiphersuites.Combination best = preferences[0].Aead
                .FirstOrDefault(c => c.SymmetricAlgorithm == SymmetricKeyAlgorithmTag.Aes256 && IsCommon(c));
            if (best != null)
                return best;

            best = preferences[0].Aead.FirstOrDefault(IsCommon);
            return best ?? Aes128Ocb;
        }

        private static SymmetricKeyAlgorithmTag SelectCipher(List<Preferences> preferences)
        {
            bool IsCommon(SymmetricKeyAlgorithmTag a) => preferences.All(p => p.Symmetric.Contains(a));
            bool AesOnly = preferences.Any(p => p.RequiresAes);

            if (IsCommon(SymmetricKeyAlgorithmTag.Aes256))
                return SymmetricKeyAlgorithmTag.Aes256;

            foreach (SymmetricKeyAlgorithmTag candidate in preferences[0].Symmetric)
            {
                if (AesOnly && !IsAes(candidate))
                    continue;
                if (IsCommon(candidate))
                    return candidate;
            }

            return SymmetricKeyAlgorithmTag.Aes128;
        }

        private static bool IsAes(SymmetricKeyAlgorithmTag algorithm) =>
            algorithm == SymmetricKeyAlgorithmTag.Aes128
            || algorithm == SymmetricKeyAlgorithmTag.Aes192
            || algorithm == SymmetricKeyAlgorithmTag.Aes256;

        /// <remarks>RFC 9580 9.3: IDEA, TripleDES and CAST5 are only for decryption, so they are not chosen.</remarks>
        private static bool IsUsableCipher(int algorithm)
        {
            switch ((SymmetricKeyAlgorithmTag)algorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
            case SymmetricKeyAlgorithmTag.Twofish:
            case SymmetricKeyAlgorithmTag.Blowfish:
                return true;
            default:
                return false;
            }
        }

        private static bool IsUsableAeadMode(AeadAlgorithmTag algorithm) =>
            algorithm == AeadAlgorithmTag.Eax || algorithm == AeadAlgorithmTag.Ocb || algorithm == AeadAlgorithmTag.Gcm;

        private static Preferences GetPreferences(PgpPublicKeyRing certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            PgpPublicKey primary = certificate.GetPublicKey();
            PgpSignature source = FindPreferenceSource(primary);
            PgpSignatureSubpacketVector hashed = source?.GetHashedSubPackets();

            // RFC 9580 5.2.3.10: a valid direct-key signature has to be present before a version 6 key is used
            if (primary.Version == PublicKeyPacket.Version6 && (source == null || IsRevoked(primary)))
            {
                throw new ArgumentException("version 6 certificate without a valid direct-key signature, or revoked",
                    "recipientCertificates");
            }

            var result = new Preferences();

            int[] explicitCiphers = hashed?.GetPreferredSymmetricAlgorithms();
            if (explicitCiphers != null)
            {
                result.Symmetric.AddRange(
                    explicitCiphers.Where(IsUsableCipher).Select(a => (SymmetricKeyAlgorithmTag)a));
            }

            PreferredAeadCiphersuites ciphersuites = hashed?.GetPreferredAeadCiphersuites();
            if (ciphersuites != null)
            {
                result.Aead.AddRange(ciphersuites.GetRawAlgorithms().Where(c =>
                    PgpAead.IsSupportedCipher(c.SymmetricAlgorithm) && IsUsableAeadMode(c.AeadAlgorithm)));
            }

            // RFC 9980 7.1: a certificate with post-quantum keys implicitly supports AES-256 (after the explicit
            // preferences), and AES-128 is always supported. Anybody can append a subkey to a certificate, so a subkey
            // only counts with a binding signature.
            bool postQuantum = PgpUtilities.IsRfc9980Algorithm(primary.Algorithm) || certificate.GetPublicKeys()
                .Skip(1).Any(k => PgpUtilities.IsRfc9980Algorithm(k.Algorithm) && IsBound(k, primary));
            if (postQuantum && !result.Symmetric.Contains(SymmetricKeyAlgorithmTag.Aes256))
            {
                result.Symmetric.Add(SymmetricKeyAlgorithmTag.Aes256);
            }
            if (!result.Symmetric.Contains(SymmetricKeyAlgorithmTag.Aes128))
            {
                result.Symmetric.Add(SymmetricKeyAlgorithmTag.Aes128);
            }

            if (postQuantum && !result.Aead.Contains(Aes256Ocb))
            {
                result.Aead.Add(Aes256Ocb);
            }
            if (!result.Aead.Contains(Aes128Ocb))
            {
                result.Aead.Add(Aes128Ocb);
            }

            // RFC 9580 13.7: version 6 certificates without a Features subpacket support version 2 SEIPD
            Features features = hashed?.GetFeatures();
            result.SupportsSeipdV2 = features != null
                ? features.SupportsSeipdV2()
                : source != null && primary.Version == PublicKeyPacket.Version6;

            // RFC 9580 5.1.6, 5.1.7, RFC 9980 4.3.1: X25519, X448 and ML-KEM recipients only get AES in a v3 PKESK
            result.RequiresAes = certificate.GetPublicKeys().Any(k => k.IsEncryptionKey &&
                (k.Algorithm == PublicKeyAlgorithmTag.X25519 || k.Algorithm == PublicKeyAlgorithmTag.X448 ||
                 PgpUtilities.IsCompositeKemAlgorithm(k.Algorithm)));

            return result;
        }

        /// <summary>The newest self-signature of the certificate that verifies and carries the preferences.</summary>
        private static PgpSignature FindPreferenceSource(PgpPublicKey primary)
        {
            if (primary.Version == PublicKeyPacket.Version6)
                return NewestVerifyingDirectKeySignature(primary);

            // version 4: the certification of the primary user ID, or else a direct-key signature. The newest valid
            // self-signature of a user ID replaces the older ones, the primary user ID flag included, and a
            // revocation removes the user ID.
            PgpSignature newest = null, newestPrimary = null;
            // the raw user IDs, since the strings of GetUserIds() are not decoded as UTF-8
            foreach (byte[] id in primary.GetRawUserIds())
            {
                PgpSignature current = CurrentSelfCertification(primary, primary.GetSignaturesForId(id),
                    signature => VerifiesCertification(signature, id, primary));
                if (current == null)
                    continue;

                if (IsNewer(current, newest))
                {
                    newest = current;
                }
                if (current.GetHashedSubPackets()?.IsPrimaryUserId() == true && IsNewer(current, newestPrimary))
                {
                    newestPrimary = current;
                }
            }

            // user attributes have self-signatures like user IDs (RFC 9580 5.12)
            foreach (PgpUserAttributeSubpacketVector attributes in primary.GetUserAttributes())
            {
                PgpSignature current = CurrentSelfCertification(primary,
                    primary.GetSignaturesForUserAttribute(attributes),
                    signature => VerifiesCertification(signature, attributes, primary));
                if (current != null && IsNewer(current, newest))
                {
                    newest = current;
                }
            }

            return newestPrimary ?? newest ?? NewestVerifyingDirectKeySignature(primary);
        }

        /// <summary>
        /// The current self-signature of a user ID or user attribute: its newest certification that verifies and is
        /// in effect, or null if there is none or a newer certification revocation retires the user ID. Such a
        /// revocation spares only the non-revocable certifications (RFC 9580 5.2.3.20), the newest of which then
        /// applies, without the properties of the newer certifications that it revokes.
        /// </summary>
        private static PgpSignature CurrentSelfCertification(PgpPublicKey primary,
            IEnumerable<PgpSignature> signatures, Func<PgpSignature, bool> verifies)
        {
            PgpSignature certification = null, revocation = null;
            PgpSignature irrevocable = null;
            foreach (PgpSignature signature in signatures)
            {
                if (!IsSelfSignatureOnUserId(signature, primary) || !IsInEffect(signature) || !verifies(signature))
                    continue;

                if (signature.SignatureType == PgpSignature.CertificationRevocation)
                {
                    if (IsNewer(signature, revocation))
                    {
                        revocation = signature;
                    }
                    continue;
                }

                if (IsNewer(signature, certification))
                {
                    certification = signature;
                }
                if (signature.GetHashedSubPackets()?.IsRevocable() == false && IsNewer(signature, irrevocable))
                {
                    irrevocable = signature;
                }
            }

            bool revoked = revocation != null && IsNewer(revocation, certification);
            return revoked ? irrevocable : certification;
        }

        private static bool IsSelfSignatureOnUserId(PgpSignature signature, PgpPublicKey primary)
        {
            int type = signature.SignatureType;
            return signature.KeyId == primary.KeyId && (type == PgpSignature.CertificationRevocation ||
                type >= PgpSignature.DefaultCertification && type <= PgpSignature.PositiveCertification);
        }

        /// <summary>Whether the primary key has a revocation signature of its own that verifies.</summary>
        private static bool IsRevoked(PgpPublicKey primary)
        {
            foreach (PgpSignature revocation in primary.GetSignaturesOfType(PgpSignature.KeyRevocation))
            {
                try
                {
                    revocation.InitVerify(primary);
                    if (revocation.VerifyCertification(primary))
                        return true;
                }
                catch (Exception e) when (e is PgpException || e is InvalidOperationException || e is ArgumentException)
                {
                }
            }
            return false;
        }

        /// <summary>Whether the signature is made by now, and not expired (RFC 9580 5.2.3.18).</summary>
        private static bool IsInEffect(PgpSignature signature)
        {
            DateTime now = DateTime.UtcNow;
            if (signature.CreationTime > now)
                return false;

            long seconds = signature.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0;
            return seconds <= 0 || signature.CreationTime.AddSeconds(seconds) > now;
        }

        private static bool IsNewer(PgpSignature signature, PgpSignature than) =>
            than == null || signature.CreationTime > than.CreationTime;

        private static bool VerifiesCertification(PgpSignature signature, byte[] id, PgpPublicKey primary)
        {
            try
            {
                signature.InitVerify(primary);
                return signature.VerifyCertification(id, primary);
            }
            catch (Exception e) when (e is PgpException || e is InvalidOperationException || e is ArgumentException)
            {
                return false;
            }
        }

        private static bool VerifiesCertification(PgpSignature signature, PgpUserAttributeSubpacketVector attributes,
            PgpPublicKey primary)
        {
            try
            {
                signature.InitVerify(primary);
                return signature.VerifyCertification(attributes, primary);
            }
            catch (Exception e) when (e is PgpException || e is InvalidOperationException || e is ArgumentException)
            {
                return false;
            }
        }

        private static bool IsBound(PgpPublicKey subkey, PgpPublicKey primary)
        {
            foreach (PgpSignature binding in subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding))
            {
                try
                {
                    binding.InitVerify(primary);
                    if (binding.VerifyCertification(primary, subkey))
                        return true;
                }
                catch (Exception e) when (e is PgpException || e is InvalidOperationException || e is ArgumentException)
                {
                }
            }
            return false;
        }

        private static PgpSignature NewestVerifyingDirectKeySignature(PgpPublicKey primary)
        {
            PgpSignature newest = null;
            foreach (PgpSignature signature in primary.GetSignaturesOfType(PgpSignature.DirectKey))
            {
                if (signature.KeyId != primary.KeyId || !IsNewer(signature, newest) || !IsInEffect(signature))
                    continue;

                try
                {
                    signature.InitVerify(primary);
                    if (signature.VerifyCertification(primary))
                    {
                        newest = signature;
                    }
                }
                catch (Exception e) when (e is PgpException || e is InvalidOperationException || e is ArgumentException)
                {
                }
            }
            return newest;
        }

        private readonly bool m_useSeipdV2;
        private readonly SymmetricKeyAlgorithmTag m_symmetricAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;

        private PgpEncryptionPreferences(bool useSeipdV2, SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
        {
            m_useSeipdV2 = useSeipdV2;
            m_symmetricAlgorithm = symmetricAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
        }

        /// <summary>Whether every recipient supports version 2 SEIPD packets (and version 6 PKESK packets).</summary>
        public bool UseSeipdV2 => m_useSeipdV2;

        /// <summary>The symmetric cipher of the message.</summary>
        public SymmetricKeyAlgorithmTag SymmetricAlgorithm => m_symmetricAlgorithm;

        /// <summary>The AEAD mode of the message; it only matters if <see cref="UseSeipdV2"/> is set.</summary>
        public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

        /// <summary>Create an encrypted data generator for the chosen format and algorithms.</summary>
        /// <param name="random">Source of randomness.</param>
        public PgpEncryptedDataGenerator CreateGenerator(SecureRandom random) => m_useSeipdV2
            ? new PgpEncryptedDataGenerator(m_symmetricAlgorithm, m_aeadAlgorithm, random)
            : new PgpEncryptedDataGenerator(m_symmetricAlgorithm, true, random);
    }
}
