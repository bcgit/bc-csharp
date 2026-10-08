using System;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>
	/// Generator for a PGP master and subkey ring.
	/// This class will generate both the secret and public key rings
	/// </remarks>
    public class PgpKeyRingGenerator
    {
        private IList<PgpSecretKey>         keys = new List<PgpSecretKey>();
        private string                      id;
        private SymmetricKeyAlgorithmTag	encAlgorithm;
        private HashAlgorithmTag            hashAlgorithm;
        private int                         certificationLevel;
        private byte[]                      rawPassPhrase;
		private bool						useSha1;
		private PgpKeyPair                  masterKey;
        private PgpSignatureSubpacketVector hashedPacketVector;
        private PgpSignatureSubpacketVector unhashedPacketVector;
        private SecureRandom				rand;
        private PgpSecretKeyProtection      m_protection;
        private DateTime                    m_signatureTime;
        private bool                        m_finished;
        private PgpSignature                m_directKeySignature;
        private bool                        m_postQuantum;

		/// <summary>
		/// Create a new key ring generator.
		/// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
		/// <param name="masterKey">The master key pair.</param>
		/// <param name="id">The id to be associated with the ring.</param>
		/// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
		/// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
		/// <param name="useSha1">
		/// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
		/// always use SHA1 (RFC 9580 3.7.2.1).
		/// </param>
		/// <param name="hashedPackets">Packets to be included in the certification hash.</param>
		/// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
		/// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int							certificationLevel,
            PgpKeyPair					masterKey,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            char[]						passPhrase,
			bool						useSha1,
			PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
            : this(certificationLevel, masterKey, id, encAlgorithm, false, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="utf8PassPhrase">
        /// If true, conversion of the passphrase to bytes uses UTF8, otherwise the conversion
        /// is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7 and earlier).
        /// </param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">
        /// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
        /// always use SHA1 (RFC 9580 3.7.2.1).
        /// </param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int							certificationLevel,
            PgpKeyPair					masterKey,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            bool                        utf8PassPhrase,
            char[]						passPhrase,
			bool						useSha1,
			PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
            : this(certificationLevel, masterKey, id, encAlgorithm,
                PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase),
                useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
		/// Create a new key ring generator.
		/// </summary>
		/// <param name="certificationLevel">The certification level for keys on this ring.</param>
		/// <param name="masterKey">The master key pair.</param>
		/// <param name="id">The id to be associated with the ring.</param>
		/// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
		/// <param name="rawPassPhrase">The passPhrase to be used to protect secret keys.</param>
		/// <param name="useSha1">
		/// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
		/// always use SHA1 (RFC 9580 3.7.2.1).
		/// </param>
		/// <param name="hashedPackets">Packets to be included in the certification hash.</param>
		/// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
		/// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int							certificationLevel,
            PgpKeyPair					masterKey,
            string						id,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            byte[]						rawPassPhrase,
			bool						useSha1,
			PgpSignatureSubpacketVector	hashedPackets,
            PgpSignatureSubpacketVector	unhashedPackets,
            SecureRandom				rand)
        {
            this.certificationLevel = certificationLevel;
            if (PgpUtilities.IsCompositeKemAlgorithm(masterKey.PublicKey.Algorithm))
                throw new ArgumentException("ML-KEM composite keys cannot be used for a master key", nameof(masterKey));

            this.masterKey = masterKey;
            this.id = id;
            this.encAlgorithm = encAlgorithm;
            this.rawPassPhrase = rawPassPhrase;
			this.useSha1 = useSha1;
			this.hashedPacketVector = hashedPackets;
            this.unhashedPacketVector = unhashedPackets;
            this.rand = rand;

            PgpSignatureSubpacketVector preferences = PreferencesForPrimaryKey(hashedPackets);
			keys.Add(new PgpSecretKey(certificationLevel, masterKey, id, encAlgorithm, rawPassPhrase, false, useSha1,
                preferences, unhashedPackets, rand));
            NoteVersion6DirectKeySignature();
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">
        /// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
        /// always use SHA1 (RFC 9580 3.7.2.1).
        /// </param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int                         certificationLevel,
            PgpKeyPair                  masterKey,
            string                      id,
            SymmetricKeyAlgorithmTag    encAlgorithm,
            HashAlgorithmTag            hashAlgorithm,
            char[]                      passPhrase,
            bool                        useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom                rand)
            : this(certificationLevel, masterKey, id, encAlgorithm, hashAlgorithm, false, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="utf8PassPhrase">
        /// If true, conversion of the passphrase to bytes uses UTF8, otherwise the conversion
        /// is performed using Convert.ToByte(), which is the historical behaviour of the library (1.7 and earlier).
        /// </param>
        /// <param name="passPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">
        /// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
        /// always use SHA1 (RFC 9580 3.7.2.1).
        /// </param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int                         certificationLevel,
            PgpKeyPair                  masterKey,
            string                      id,
            SymmetricKeyAlgorithmTag    encAlgorithm,
            HashAlgorithmTag            hashAlgorithm,
            bool                        utf8PassPhrase,
            char[]                      passPhrase,
            bool                        useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom                rand)
            : this(certificationLevel, masterKey, id, encAlgorithm, hashAlgorithm,
                PgpUtilities.EncodePassPhrase(passPhrase, utf8PassPhrase),
                useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Create a new key ring generator.
        /// </summary>
        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        /// <param name="certificationLevel">The certification level for keys on this ring.</param>
        /// <param name="masterKey">The master key pair.</param>
        /// <param name="id">The id to be associated with the ring.</param>
        /// <param name="encAlgorithm">The algorithm to be used to protect secret keys.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="rawPassPhrase">The passPhrase to be used to protect secret keys.</param>
        /// <param name="useSha1">
        /// Checksum the secret keys with SHA1 rather than the older 16 bit checksum; protected version 4 and 6 keys
        /// always use SHA1 (RFC 9580 3.7.2.1).
        /// </param>
        /// <param name="hashedPackets">Packets to be included in the certification hash.</param>
        /// <param name="unhashedPackets">Packets to be attached unhashed to the certification.</param>
        /// <param name="rand">input secured random.</param>
        public PgpKeyRingGenerator(
            int                         certificationLevel,
            PgpKeyPair                  masterKey,
            string                      id,
            SymmetricKeyAlgorithmTag    encAlgorithm,
            HashAlgorithmTag            hashAlgorithm,
            byte[]                      rawPassPhrase,
            bool                        useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom                rand)
        {
            this.certificationLevel = certificationLevel;
            if (PgpUtilities.IsCompositeKemAlgorithm(masterKey.PublicKey.Algorithm))
                throw new ArgumentException("ML-KEM composite keys cannot be used for a master key", nameof(masterKey));

            this.masterKey = masterKey;
            this.id = id;
            this.encAlgorithm = encAlgorithm;
            this.rawPassPhrase = rawPassPhrase;
            this.useSha1 = useSha1;
            this.hashedPacketVector = hashedPackets;
            this.unhashedPacketVector = unhashedPackets;
            this.rand = rand;
            this.hashAlgorithm = hashAlgorithm;

            PgpSignatureSubpacketVector preferences = PreferencesForPrimaryKey(hashedPackets);
            keys.Add(new PgpSecretKey(certificationLevel, masterKey, id, encAlgorithm, hashAlgorithm, rawPassPhrase,
                false, useSha1, preferences, unhashedPackets, rand));
            NoteVersion6DirectKeySignature();
        }

        /// <summary>
        /// Create a key ring generator that starts with a direct-key signature on the primary key instead of a user
        /// ID certification. This is the form of RFC 9580 version 6 certificates, and it works for version 4 keys too.
        /// </summary>
        /// <remarks>
        /// User IDs are added with <see cref="AddUserId(string, int, PgpSignatureSubpacketVector,
        /// PgpSignatureSubpacketVector)"/>. The subkeys must have the same version as the primary key. A signing
        /// subkey whose hashed packets carry the sign key flag gets a primary key binding signature automatically.
        /// Put the preferences in <paramref name="directKeyHashedPackets"/>: the generator only adds AES-256 and
        /// AES-128 (with OCB) where they are missing for a certificate with keys of the RFC 9980 algorithms.
        /// The generator wipes the pass phrase of <paramref name="protection"/> when the secret key ring is
        /// generated, after which no more keys can be added and the protection cannot be used again.
        /// </remarks>
        /// <param name="masterKey">The primary key pair; it has to be able to sign.</param>
        /// <param name="hashAlgorithm">The hash algorithm for the signatures made by the generator.</param>
        /// <param name="directKeyHashedPackets">Hashed subpackets of the direct-key signature.</param>
        /// <param name="directKeyUnhashedPackets">Unhashed subpackets of the direct-key signature.</param>
        /// <param name="protection">How the secret keys are protected.</param>
        /// <param name="random">Source of randomness.</param>
        public PgpKeyRingGenerator(
            PgpKeyPair                  masterKey,
            HashAlgorithmTag            hashAlgorithm,
            PgpSignatureSubpacketVector directKeyHashedPackets,
            PgpSignatureSubpacketVector directKeyUnhashedPackets,
            PgpSecretKeyProtection      protection,
            SecureRandom                random)
        {
            if (masterKey == null)
                throw new ArgumentNullException(nameof(masterKey));
            if (protection == null)
                throw new ArgumentNullException(nameof(protection));
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            protection.CheckNotCleared();

            try
            {
                if (!PgpUtilities.IsSigningAlgorithm(masterKey.PublicKey.Algorithm))
                    throw new ArgumentException("The primary key has to be able to sign", nameof(masterKey));
                if (masterKey.PublicKey.Version == PublicKeyPacket.Version6 &&
                    PgpUtilities.GetV6SaltSize(hashAlgorithm) < 0)
                {
                    throw new ArgumentException("This hash algorithm cannot be used in version 6 signatures",
                        nameof(hashAlgorithm));
                }

                this.masterKey = masterKey;
                this.hashAlgorithm = hashAlgorithm;
                this.encAlgorithm = SymmetricKeyAlgorithmTag.Null;
                this.rand = random;
                this.m_protection = protection;

                // signature creation times have a resolution of one second
                DateTime now = DateTime.UtcNow;
                now = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
                this.m_signatureTime = masterKey.PublicKey.CreationTime > now ? masterKey.PublicKey.CreationTime : now;

                PgpSignatureGenerator sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, hashAlgorithm);
                sGen.InitSign(PgpSignature.DirectKey, masterKey.PrivateKey, random);
                sGen.SetHashedSubpackets(WithSignatureTime(PreferencesForPrimaryKey(directKeyHashedPackets)));
                sGen.SetUnhashedSubpackets(directKeyUnhashedPackets);

                m_directKeySignature = sGen.GenerateCertification(masterKey.PublicKey);
                PgpPublicKey publicKey = PgpPublicKey.AddCertification(masterKey.PublicKey, m_directKeySignature);

                keys.Add(new PgpSecretKey(masterKey.PrivateKey, publicKey, protection, random, isMasterKey: true));
            }
            catch (Exception)
            {
                protection.Clear();
                throw;
            }
        }

        /// <summary>Certify a user ID on the primary key of a generator made for direct-key signatures.</summary>
        /// <param name="id">The user ID.</param>
        /// <param name="certificationType">One of the certification types 0x10 to 0x13.</param>
        /// <param name="hashedPackets">Hashed subpackets of the certification.</param>
        /// <param name="unhashedPackets">Unhashed subpackets of the certification.</param>
        public void AddUserId(string id, int certificationType, PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            AddUserId(Strings.ToUtf8ByteArray(id), certificationType, hashedPackets, unhashedPackets);
        }

        /// <summary>Certify a user ID given as raw octets, see the overload that takes a string.</summary>
        public void AddUserId(byte[] rawId, int certificationType, PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets)
        {
            if (rawId == null)
                throw new ArgumentNullException(nameof(rawId));
            if (certificationType < PgpSignature.DefaultCertification ||
                certificationType > PgpSignature.PositiveCertification)
            {
                throw new ArgumentException("Not a user ID certification type: " + certificationType,
                    nameof(certificationType));
            }
            if (m_protection == null)
                throw new InvalidOperationException("This generator already certifies a user ID");
            CheckNotFinished();

            try
            {
                PgpSignatureGenerator sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, hashAlgorithm);
                sGen.InitSign(certificationType, masterKey.PrivateKey, rand);
                sGen.SetHashedSubpackets(WithSignatureTime(hashedPackets));
                sGen.SetUnhashedSubpackets(unhashedPackets);

                PgpSecretKey master = keys[0];
                PgpSignature certification = sGen.GenerateCertificationForRawId(rawId, masterKey.PublicKey);
                keys[0] = PgpSecretKey.ReplacePublicKey(master,
                    PgpPublicKey.AddRawIdCertification(master.PublicKey, rawId, certification));
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception adding user ID: ", e);
            }
        }

        /// <summary>
        /// RFC 9580 5.2.3.10, 10.1.1: a version 6 key is not used without a direct-key signature, which also holds its
        /// preferences. With a user ID, PgpSecretKey makes it along with the certification of the user ID.
        /// </summary>
        private void NoteVersion6DirectKeySignature()
        {
            if (masterKey.PublicKey.Version != PublicKeyPacket.Version6)
                return;

            foreach (PgpSignature signature in keys[0].PublicKey.GetSignaturesOfType(PgpSignature.DirectKey))
            {
                m_directKeySignature = signature;
            }
        }

        /// <summary>
        /// The hashed subpackets of a self-signature of a generator made for direct-key signatures. The generator makes
        /// the direct-key signature and the user ID certifications at one time, so that implementations that take the
        /// properties of the primary key from its newest self-signature find them in the direct-key signature, however
        /// long the protection of the secret keys takes (as with the key generator of Bouncy Castle Java). A binding
        /// signature is not older than its subkey. A creation time given in the subpackets is kept.
        /// </summary>
        private PgpSignatureSubpacketVector WithSignatureTime(PgpSignatureSubpacketVector hashedPackets,
            PgpPublicKey subkey = null)
        {
            if (m_protection == null || (hashedPackets != null && hashedPackets.HasSignatureCreationTime()))
                return hashedPackets;

            DateTime time = subkey != null && subkey.CreationTime > m_signatureTime
                ? subkey.CreationTime
                : m_signatureTime;
            var generator = hashedPackets == null
                ? new PgpSignatureSubpacketGenerator()
                : new PgpSignatureSubpacketGenerator(hashedPackets);
            generator.SetSignatureCreationTime(false, time);
            return generator.Generate();
        }

        /// <summary>
        /// RFC 9980 7.1: a certificate with keys of the RFC 9980 algorithms should list AES-256 in its preferred
        /// symmetric algorithms and AES-256 with OCB in its preferred AEAD ciphersuites. Where the self-signature has
        /// no such list, one is added, with AES-128 after AES-256. The AEAD ciphersuites concern v2 SEIPD, which
        /// version 6 keys support and other keys announce in their features.
        /// </summary>
        /// <returns>The subpackets with the lists added, or null if they are there already.</returns>
        private static PgpSignatureSubpacketVector WithPostQuantumPreferences(PgpSignatureSubpacketVector hashedPackets,
            int keyVersion)
        {
            Features features = hashedPackets?.GetFeatures();
            bool seipdV2 = keyVersion == PublicKeyPacket.Version6 || (features != null && features.SupportsSeipdV2());

            bool addSymmetric = hashedPackets == null ||
                !hashedPackets.HasSubpacket(SignatureSubpacketTag.PreferredSymmetricAlgorithms);
            bool addAead = seipdV2 && (hashedPackets == null ||
                !hashedPackets.HasSubpacket(SignatureSubpacketTag.PreferredAeadAlgorithms));
            if (!addSymmetric && !addAead)
                return null;

            var generator = new PgpSignatureSubpacketGenerator(hashedPackets);
            if (addSymmetric)
            {
                generator.SetPreferredSymmetricAlgorithms(false,
                    new int[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            }
            if (addAead)
            {
                generator.SetPreferredAeadCiphersuites(false, new PreferredAeadCiphersuites.Combination[]
                {
                    new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb),
                    new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb),
                });
            }
            return generator.Generate();
        }

        /// <summary>The subpackets of the self-signature with the preferences, for the primary key.</summary>
        private PgpSignatureSubpacketVector PreferencesForPrimaryKey(PgpSignatureSubpacketVector hashedPackets)
        {
            if (!PgpUtilities.IsRfc9980Algorithm(masterKey.PublicKey.Algorithm))
                return hashedPackets;

            m_postQuantum = true;
            return WithPostQuantumPreferences(hashedPackets, masterKey.PublicKey.Version) ?? hashedPackets;
        }

        /// <summary>
        /// When the first subkey of the RFC 9980 algorithms is added, the self-signature with the preferences is made
        /// again if they lack AES-256 (see <see cref="WithPostQuantumPreferences"/>): the direct-key signature, or the
        /// certification of the user ID for a generator made with one.
        /// </summary>
        private void NotePostQuantumSubkey(PgpKeyPair keyPair)
        {
            if (m_postQuantum || !PgpUtilities.IsRfc9980Algorithm(keyPair.PublicKey.Algorithm))
                return;

            m_postQuantum = true;

            PgpSecretKey master = keys[0];
            PgpSignature old = m_directKeySignature;
            if (old == null)
            {
                foreach (PgpSignature certification in master.PublicKey.GetSignaturesForId(id))
                {
                    old = certification;
                    break;
                }
            }

            PgpSignatureSubpacketVector hashed = old == null
                ? null
                : WithPostQuantumPreferences(old.GetHashedSubPackets(), masterKey.PublicKey.Version);
            if (hashed == null)
                return;

            var sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, old.HashAlgorithm);
            sGen.InitSign(old.SignatureType, masterKey.PrivateKey, rand);
            sGen.SetHashedSubpackets(hashed);
            sGen.SetUnhashedSubpackets(old.GetUnhashedSubPackets());

            PgpPublicKey publicKey;
            if (m_directKeySignature != null)
            {
                m_directKeySignature = sGen.GenerateCertification(masterKey.PublicKey);
                publicKey = PgpPublicKey.AddCertification(PgpPublicKey.RemoveCertification(master.PublicKey, old),
                    m_directKeySignature);
            }
            else
            {
                PgpSignature certification = sGen.GenerateCertification(id, masterKey.PublicKey);
                publicKey = PgpPublicKey.AddCertification(PgpPublicKey.RemoveCertification(master.PublicKey, id, old),
                    id, certification);
            }
            keys[0] = PgpSecretKey.ReplacePublicKey(master, publicKey);
        }

        private void CheckNotFinished()
        {
            if (m_finished)
                throw new InvalidOperationException("The secret key ring has been generated");
        }

        private void CheckSubkey(PgpKeyPair keyPair)
        {
            if (keyPair == null)
                throw new ArgumentNullException(nameof(keyPair));
            if (keyPair.PublicKey.Version != masterKey.PublicKey.Version)
                throw new ArgumentException("The subkey has to have the version of the primary key", nameof(keyPair));
            CheckNotFinished();

            // the protection may have been used up by another generator or key copy since
            m_protection?.CheckNotCleared();
        }

        private PgpSecretKey CreateSubkey(PgpKeyPair keyPair, IList<PgpSignature> subSigs)
        {
            PgpPublicKey publicKey = new PgpPublicKey(keyPair.PublicKey, null, subSigs);

            return m_protection != null
                ? new PgpSecretKey(keyPair.PrivateKey, publicKey, m_protection, rand, isMasterKey: false)
                : new PgpSecretKey(keyPair.PrivateKey, publicKey, encAlgorithm, rawPassPhrase, false, useSha1, rand,
                    false);
        }

		/// <summary>Add a subkey to the key ring to be generated with default certification.</summary>
        public void AddSubKey(
            PgpKeyPair keyPair)
        {
			AddSubKey(keyPair, this.hashedPacketVector, this.unhashedPacketVector);
		}


        /// <summary>
        /// Add a subkey to the key ring to be generated with default certification.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        public void AddSubKey(PgpKeyPair keyPair, HashAlgorithmTag hashAlgorithm)
        {
            this.AddSubKey(keyPair, this.hashedPacketVector, this.unhashedPacketVector, hashAlgorithm);
        }

        /// <summary>
        /// Add a signing subkey to the key ring to be generated with default certification and a primary key binding signature.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="primaryKeyBindingHashAlgorithm">The primary-key binding hash algorithm.</param>
        public void AddSubKey(PgpKeyPair keyPair, HashAlgorithmTag hashAlgorithm, HashAlgorithmTag primaryKeyBindingHashAlgorithm)
        {
            this.AddSubKey(keyPair, this.hashedPacketVector, this.unhashedPacketVector, hashAlgorithm, primaryKeyBindingHashAlgorithm);
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification using SHA-256, or a larger hash where the keys need it.
        /// </summary>
        /// <param name="keyPair">Public/private key pair.</param>
        /// <param name="hashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(
			PgpKeyPair					keyPair,
			PgpSignatureSubpacketVector	hashedPackets,
			PgpSignatureSubpacketVector	unhashedPackets)
		{
            // RFC 9580 9.5 and RFC 9980 7.2: no bindings with SHA-1; RFC 9580 5.2.3.2-5: a hash as large as the
            // primary key and a signing subkey (for its embedded signature) need
            HashAlgorithmTag hashAlgorithm = m_protection != null
                ? this.hashAlgorithm
                : PgpUtilities.GetDefaultHashAlgorithm(masterKey.PublicKey, keyPair.PublicKey);

            AddSubKey(keyPair, hashedPackets, unhashedPackets, hashAlgorithm);
        }

        /// <summary>
        /// Add a subkey with specific hashed and unhashed packets associated with it and
        /// default certification.
        /// </summary>
        /// <param name="keyPair">Public/private key pair.</param>
        /// <param name="hashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">exception adding subkey: </exception>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(
            PgpKeyPair keyPair,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            HashAlgorithmTag hashAlgorithm)
        {
            CheckSubkey(keyPair);

            if (PgpUtilities.IsRfc9980Algorithm(keyPair.PublicKey.Algorithm) &&
                PgpUtilities.IsWeakBindingHash(hashAlgorithm))
            {
                throw new ArgumentException("Hash algorithm not allowed for subkey bindings of this algorithm",
                    nameof(hashAlgorithm));
            }

            // RFC 9580 5.2.1.8: the binding of a signing subkey embeds a signature of the subkey (a primary key binding
            // signature). A subkey signs if its key flags say so or, if it has none, if its algorithm can sign.
            bool hasFlags = hashedPackets != null && hashedPackets.HasSubpacket(SignatureSubpacketTag.KeyFlags);
            bool signs = !hasFlags || (hashedPackets.GetKeyFlags() & PgpKeyFlags.CanSign) != 0;
            if (signs && PgpUtilities.IsSigningAlgorithm(keyPair.PublicKey.Algorithm))
            {
                AddSubKey(keyPair, hashedPackets, unhashedPackets, hashAlgorithm,
                    m_protection != null ? this.hashAlgorithm : hashAlgorithm);
                return;
            }

            try
            {
                PgpSignatureGenerator sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, hashAlgorithm);

                //
                // Generate the certification
                //
                sGen.InitSign(PgpSignature.SubkeyBinding, masterKey.PrivateKey);

                sGen.SetHashedSubpackets(WithSignatureTime(hashedPackets, keyPair.PublicKey));
                sGen.SetUnhashedSubpackets(unhashedPackets);

                var subSigs = new List<PgpSignature>();
                subSigs.Add(sGen.GenerateCertification(masterKey.PublicKey, keyPair.PublicKey));

                PgpSecretKey subkey = CreateSubkey(keyPair, subSigs);
                NotePostQuantumSubkey(keyPair);
                keys.Add(subkey);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception adding subkey: ", e);
            }
        }

        /// <summary>
        /// Add a signing subkey with specific hashed and unhashed packets associated with it and
        /// default certifications, including the primary-key binding signature.
        /// </summary>
        /// <param name="keyPair">Public/private key pair.</param>
        /// <param name="hashedPackets">Hashed packet values to be included in certification.</param>
        /// <param name="unhashedPackets">Unhashed packets values to be included in certification.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="primaryKeyBindingHashAlgorithm">The primary-key binding hash algorithm.</param>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">exception adding subkey: </exception>
        /// <exception cref="PgpException"></exception>
        public void AddSubKey(
            PgpKeyPair keyPair,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            HashAlgorithmTag hashAlgorithm,
            HashAlgorithmTag primaryKeyBindingHashAlgorithm)
        {
            CheckSubkey(keyPair);

            if (PgpUtilities.IsCompositeKemAlgorithm(keyPair.PublicKey.Algorithm))
                throw new ArgumentException("ML-KEM composite keys are not signing algorithms", nameof(keyPair));

            try
            {
                PgpSignatureGenerator sGen = new PgpSignatureGenerator(masterKey.PublicKey.Algorithm, hashAlgorithm);

                //
                // Generate the certification
                //
                sGen.InitSign(PgpSignature.SubkeyBinding, masterKey.PrivateKey);

                // add primary key binding subpacket
                PgpSignatureGenerator pGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, primaryKeyBindingHashAlgorithm);

                pGen.InitSign(PgpSignature.PrimaryKeyBinding, keyPair.PrivateKey);
                if (m_protection != null)
                {
                    pGen.SetHashedSubpackets(WithSignatureTime(null, keyPair.PublicKey));
                }

                PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator(
                    WithSignatureTime(hashedPackets, keyPair.PublicKey));

                spGen.AddEmbeddedSignature(false,
                        pGen.GenerateCertification(masterKey.PublicKey, keyPair.PublicKey));
                
                sGen.SetHashedSubpackets(spGen.Generate());
                sGen.SetUnhashedSubpackets(unhashedPackets);

                var subSigs = new List<PgpSignature>();
                subSigs.Add(sGen.GenerateCertification(masterKey.PublicKey, keyPair.PublicKey));

                PgpSecretKey subkey = CreateSubkey(keyPair, subSigs);
                NotePostQuantumSubkey(keyPair);
                keys.Add(subkey);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception adding subkey: ", e);
            }
        }

        /// <summary>Return the secret key ring.</summary>
        public PgpSecretKeyRing GenerateSecretKeyRing()
        {
            var ring = new PgpSecretKeyRing(keys);

            if (m_protection != null && !m_finished)
            {
                // all the keys are protected by now, and the pass phrase is not needed any more
                m_protection.Clear();
                m_finished = true;
            }

            return ring;
        }

		/// <summary>Return the public key ring that corresponds to the secret key ring.</summary>
        public PgpPublicKeyRing GeneratePublicKeyRing()
        {
            var pubKeys = new List<PgpPublicKey>();

            var enumerator = keys.GetEnumerator();
            enumerator.MoveNext();

			PgpSecretKey pgpSecretKey = enumerator.Current;
			pubKeys.Add(pgpSecretKey.PublicKey);

			while (enumerator.MoveNext())
            {
                pgpSecretKey = enumerator.Current;

				PgpPublicKey k = new PgpPublicKey(pgpSecretKey.PublicKey);
				k.publicPk = new PublicSubkeyPacket((byte)k.Version, k.Algorithm, k.CreationTime, k.publicPk.Key);

				pubKeys.Add(k);
			}

			return new PgpPublicKeyRing(pubKeys);
        }
    }
}
