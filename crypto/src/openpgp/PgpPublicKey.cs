using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to handle a PGP public key object.</remarks>
    public class PgpPublicKey
        : PgpObject
    {
        // We default to these as they are specified as mandatory in RFC 6631.
        private static readonly PgpKdfParameters DefaultKdfParameters = new PgpKdfParameters(HashAlgorithmTag.Sha256,
            SymmetricKeyAlgorithmTag.Aes128);

        public static byte[] CalculateFingerprint(PublicKeyPacket publicPk)
        {
            IBcpgKey key = publicPk.Key;
            IDigest digest;

            if (publicPk.Version <= PublicKeyPacket.Version3)
            {
                if (!(key is RsaPublicBcpgKey rK))
                    throw new PgpException("Version 3 OpenPGP keys can only use RSA. Found " + Platform.GetTypeName(key));

                try
                {
                    digest = PgpUtilities.CreateDigest(HashAlgorithmTag.MD5);

                    UpdateDigest(digest, rK.Modulus);
                    UpdateDigest(digest, rK.PublicExponent);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
            else if (publicPk.Version == PublicKeyPacket.Version4)
            {
                try
                {
                    byte[] kBytes = publicPk.GetEncodedContents();

                    digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);

                    digest.Update(0x99);
                    digest.Update((byte)(kBytes.Length >> 8));
                    digest.Update((byte)kBytes.Length);
                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
            else if (publicPk.Version == PublicKeyPacket.LibrePgp5 || publicPk.Version == PublicKeyPacket.Version6)
            {
                try
                {
                    byte[] kBytes = publicPk.GetEncodedContents();

                    digest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256);

                    digest.Update((byte)(publicPk.Version == PublicKeyPacket.Version6 ? 0x9B : 0x9A));

                    digest.Update((byte)(kBytes.Length >> 24));
                    digest.Update((byte)(kBytes.Length >> 16));
                    digest.Update((byte)(kBytes.Length >> 8));
                    digest.Update((byte)kBytes.Length);
                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
            else
            {
                throw new UnsupportedPacketVersionException("Unsupported PGP key version: " + publicPk.Version);
            }

            return DigestUtilities.DoFinal(digest);
        }

        private static void UpdateDigest(IDigest d, BigInteger b)
        {
            byte[] bytes = b.ToByteArrayUnsigned();
            d.BlockUpdate(bytes, 0, bytes.Length);
        }

        private static readonly int[] MasterKeyCertificationTypes = new int[]
        {
            PgpSignature.PositiveCertification,
            PgpSignature.CasualCertification,
            PgpSignature.NoCertification,
            PgpSignature.DefaultCertification,
            PgpSignature.DirectKey,
        };

        internal PublicKeyPacket	publicPk;
        internal TrustPacket		trustPk;
        internal IList<PgpSignature> keySigs = new List<PgpSignature>();
        internal IList<IUserDataPacket> ids = new List<IUserDataPacket>();
        internal IList<TrustPacket> idTrusts = new List<TrustPacket>();
        internal IList<IList<PgpSignature>> idSigs = new List<IList<PgpSignature>>();

        internal IList<PgpSignature> subSigs = null;

        private long keyId;
        private byte[] fingerprint;
        private int keyStrength;

        // the key parameters, made once: validating them can be costly (large RSA moduli are tested for primality)
        private AsymmetricKeyParameter m_key;

        private void Init()
        {
            IBcpgKey key = publicPk.Key;

            this.fingerprint = CalculateFingerprint(publicPk);

            if (publicPk.Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey) key;

                this.keyId = rK.Modulus.LongValue;
                this.keyStrength = rK.Modulus.BitLength;
            }
            else
            {
                this.keyId = PublicKeyPacket.GetKeyID(publicPk, fingerprint);

                if (key is RsaPublicBcpgKey)
                {
                    this.keyStrength = ((RsaPublicBcpgKey)key).Modulus.BitLength;
                }
                else if (key is DsaPublicBcpgKey)
                {
                    this.keyStrength = ((DsaPublicBcpgKey)key).P.BitLength;
                }
                else if (key is ElGamalPublicBcpgKey)
                {
                    this.keyStrength = ((ElGamalPublicBcpgKey)key).P.BitLength;
                }
                else if (key is EdDsaPublicBcpgKey eddsaK)
                {
                    var curveOid = eddsaK.CurveOid;
                    if (EdECObjectIdentifiers.id_Ed25519.Equals(curveOid) ||
                        GnuObjectIdentifiers.Ed25519.Equals(curveOid) ||
                        EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                        CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                    {
                        this.keyStrength = 256;
                    }
                    else if (EdECObjectIdentifiers.id_Ed448.Equals(curveOid) ||
                        EdECObjectIdentifiers.id_X448.Equals(curveOid))
                    {
                        this.keyStrength = 448;
                    }
                    else
                    {
                        this.keyStrength = -1; // unknown
                    }
                }
                else if (key is ECPublicBcpgKey ecK)
                {
                    var curveOid = ecK.CurveOid;
                    X9ECParametersHolder ecParameters = ECUtilities.FindECCurveByOidLazy(curveOid);

                    if (ecParameters != null)
                    {
                        this.keyStrength = ecParameters.Curve.FieldSize;
                    }
                    else
                    {
                        this.keyStrength = -1; // unknown
                    }
                }
                else if (key is X25519PublicBcpgKey || key is Ed25519PublicBcpgKey ||
                    key is MLKem768X25519PublicBcpgKey || key is MLDsa65Ed25519PublicBcpgKey)
                {
                    // the curve, also for the composite keys of RFC 9980 that are built on it
                    this.keyStrength = 256;
                }
                else if (key is X448PublicBcpgKey || key is Ed448PublicBcpgKey ||
                    key is MLKem1024X448PublicBcpgKey || key is MLDsa87Ed448PublicBcpgKey)
                {
                    this.keyStrength = 448;
                }
                else if (key is SlhDsaPublicBcpgKey slhDsaK)
                {
                    // the size of the public key, 2n octets
                    this.keyStrength = slhDsaK.Key.Length * 8;
                }
            }
        }

        /// <summary>
        /// Create a PgpPublicKey from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// </remarks>
        /// <param name="algorithm">Asymmetric algorithm type representing the public key.</param>
        /// <param name="pubKey">Actual public key to associate.</param>
        /// <param name="time">Date of creation.</param>
        /// <exception cref="ArgumentException">If <c>pubKey</c> is not public.</exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        public PgpPublicKey(PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey, DateTime time)
            : this(PublicKeyPacket.Version4, algorithm, pubKey, time)
        {
        }

        /// <summary>
        /// Create a PgpPublicKey of the given version from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// <para>
        /// Version 6 keys cannot use DSA, ElGamal, EdDSALegacy or Curve25519Legacy (RFC 9580 12.5, 12.6), and their ECDH
        /// keys have the KDF parameters that are prescribed for the curve (RFC 9580 9.2).
        /// </para>
        /// </remarks>
        /// <param name="version">The version of the key: 4 or 6.</param>
        /// <param name="algorithm">Asymmetric algorithm type representing the public key.</param>
        /// <param name="pubKey">Actual public key to associate.</param>
        /// <param name="time">Date of creation.</param>
        /// <exception cref="ArgumentException">
        /// If <c>pubKey</c> is not public, or does not fit <c>algorithm</c> or <c>version</c>.
        /// </exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        public PgpPublicKey(int version, PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey, DateTime time)
        {
            if (version != PublicKeyPacket.Version4 && version != PublicKeyPacket.Version6)
                throw new ArgumentException("The version has to be 4 or 6", nameof(version));
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected a public key", nameof(pubKey));
            if ((algorithm == PublicKeyAlgorithmTag.MLKem768_X25519) != (pubKey is MLKem768X25519PublicKeyParameters))
                throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
            if ((algorithm == PublicKeyAlgorithmTag.MLKem1024_X448) != (pubKey is MLKem1024X448PublicKeyParameters))
                throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
            if ((algorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519) != (pubKey is MLDsa65Ed25519PublicKeyParameters))
                throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
            if ((algorithm == PublicKeyAlgorithmTag.MLDsa87_Ed448) != (pubKey is MLDsa87Ed448PublicKeyParameters))
                throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
            if (PgpUtilities.IsSlhDsaAlgorithm(algorithm) != (pubKey is SlhDsaPublicKeyParameters))
                throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));

            IBcpgKey bcpgKey;
            if (pubKey is SlhDsaPublicKeyParameters slhDsaKey)
            {
                // RFC 9980 6.2: only defined for version 6 keys, and the parameter set is fixed by the algorithm
                if (version != PublicKeyPacket.Version6)
                    throw new ArgumentException("SLH-DSA can only be used in version 6 keys");
                if (slhDsaKey.Parameters != PgpUtilities.GetSlhDsaParameters(algorithm))
                    throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));

                bcpgKey = new SlhDsaPublicBcpgKey(algorithm, slhDsaKey.GetEncoded());
            }
            else if (pubKey is MLDsa65Ed25519PublicKeyParameters mlDsaEd25519Key)
            {
                // RFC 9980 5.3: only defined for version 6 keys
                if (version != PublicKeyPacket.Version6)
                    throw new ArgumentException("ML-DSA-65+Ed25519 can only be used in version 6 keys");

                bcpgKey = new MLDsa65Ed25519PublicBcpgKey(Arrays.Concatenate(mlDsaEd25519Key.Ed25519Key.GetEncoded(),
                    mlDsaEd25519Key.MLDsaKey.GetEncoded()));
            }
            else if (pubKey is MLDsa87Ed448PublicKeyParameters mlDsaEd448Key)
            {
                if (version != PublicKeyPacket.Version6)
                    throw new ArgumentException("ML-DSA-87+Ed448 can only be used in version 6 keys");

                bcpgKey = new MLDsa87Ed448PublicBcpgKey(Arrays.Concatenate(mlDsaEd448Key.Ed448Key.GetEncoded(),
                    mlDsaEd448Key.MLDsaKey.GetEncoded()));
            }
            else if (pubKey is MLKem1024X448PublicKeyParameters mlKemX448Key)
            {
                // RFC 9980 3.5: only defined for version 6 keys
                if (version != PublicKeyPacket.Version6)
                    throw new ArgumentException("ML-KEM-1024+X448 can only be used in version 6 keys");

                bcpgKey = new MLKem1024X448PublicBcpgKey(Arrays.Concatenate(mlKemX448Key.X448Key.GetEncoded(),
                    mlKemX448Key.MLKemKey.GetEncoded()));
            }
            else if (pubKey is MLKem768X25519PublicKeyParameters mlKemX25519Key)
            {
                bcpgKey = new MLKem768X25519PublicBcpgKey(Arrays.Concatenate(mlKemX25519Key.X25519Key.GetEncoded(),
                    mlKemX25519Key.MLKemKey.GetEncoded()));
            }
            else if (pubKey is RsaKeyParameters rK)
            {
                bcpgKey = new RsaPublicBcpgKey(rK.Modulus, rK.Exponent);
            }
            else if (pubKey is DsaPublicKeyParameters dK)
            {
                RequireVersion4(version, "DSA");
                DsaParameters dP = dK.Parameters;

                bcpgKey = new DsaPublicBcpgKey(dP.P, dP.Q, dP.G, dK.Y);
            }
            else if (pubKey is ElGamalPublicKeyParameters eK)
            {
                RequireVersion4(version, "ElGamal");
                ElGamalParameters eS = eK.Parameters;

                bcpgKey = new ElGamalPublicBcpgKey(eS.P, eS.G, eK.Y);
            }
            else if (pubKey is ECPublicKeyParameters ecK)
            {
                if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    // RFC 9580 9.2: the KDF and KEK parameters of version 6 keys depend on the curve
                    PgpKdfParameters kdfParams = new PgpKdfParameters(HashAlgorithmTag.Sha256,
                        SymmetricKeyAlgorithmTag.Aes128);
                    if (version == PublicKeyPacket.Version6)
                    {
                        kdfParams = PgpUtilities.GetMandatedEcdhKdfParameters(ecK.PublicKeyParamSet)
                            ?? throw new ArgumentException("This curve cannot be used for ECDH in version 6 keys",
                                nameof(pubKey));
                    }

                    bcpgKey = new ECDHPublicBcpgKey(ecK.PublicKeyParamSet, ecK.Q, kdfParams.HashAlgorithm,
                        kdfParams.SymmetricWrapAlgorithm);
                }
                else if (algorithm == PublicKeyAlgorithmTag.ECDsa)
                {
                    bcpgKey = new ECDsaPublicBcpgKey(ecK.PublicKeyParamSet, ecK.Q);
                }
                else
                {
                    throw new PgpException("unknown EC algorithm");
                }
            }
            else if (pubKey is Ed25519PublicKeyParameters ed25519PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.Ed25519)
                {
                    bcpgKey = new Ed25519PublicBcpgKey(ed25519PubKey.GetEncoded());
                }
                else if (algorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
                {
                    RequireVersion4(version, "EdDSALegacy");
                    byte[] pointEnc = new byte[1 + Ed25519PublicKeyParameters.KeySize];
                    pointEnc[0] = 0x40;
                    ed25519PubKey.Encode(pointEnc, 1);
                    bcpgKey = new EdDsaPublicBcpgKey(GnuObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
                }
                else
                {
                    throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
                }
            }
            else if (pubKey is Ed448PublicKeyParameters ed448PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.Ed448)
                {
                    bcpgKey = new Ed448PublicBcpgKey(ed448PubKey.GetEncoded());
                }
                else if (algorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
                {
                    RequireVersion4(version, "EdDSALegacy");
                    byte[] pointEnc = new byte[Ed448PublicKeyParameters.KeySize];
                    ed448PubKey.Encode(pointEnc, 0);
                    bcpgKey = new EdDsaPublicBcpgKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, pointEnc));
                }
                else
                {
                    throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
                }
            }
            else if (pubKey is X25519PublicKeyParameters x25519PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.X25519)
                {
                    bcpgKey = new X25519PublicBcpgKey(x25519PubKey.GetEncoded());
                }
                else if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    RequireVersion4(version, "Curve25519Legacy");
                    byte[] pointEnc = new byte[1 + X25519PublicKeyParameters.KeySize];
                    pointEnc[0] = 0x40;
                    x25519PubKey.Encode(pointEnc, 1);

                    PgpKdfParameters kdfParams = DefaultKdfParameters;

                    bcpgKey = new ECDHPublicBcpgKey(CryptlibObjectIdentifiers.curvey25519,
                        new BigInteger(1, pointEnc), kdfParams.HashAlgorithm, kdfParams.SymmetricWrapAlgorithm);
                }
                else
                {
                    throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
                }
            }
            else if (pubKey is X448PublicKeyParameters x448PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.X448)
                {
                    bcpgKey = new X448PublicBcpgKey(x448PubKey.GetEncoded());
                }
                else if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    RequireVersion4(version, "ECDH over X448");
                    byte[] pointEnc = new byte[X448PublicKeyParameters.KeySize];
                    x448PubKey.Encode(pointEnc, 0);

                    PgpKdfParameters kdfParams = DefaultKdfParameters;

                    bcpgKey = new ECDHPublicBcpgKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, pointEnc),
                        kdfParams.HashAlgorithm, kdfParams.SymmetricWrapAlgorithm);
                }
                else
                {
                    throw new ArgumentException("Algorithm does not match the key type", nameof(algorithm));
                }
            }
            else
            {
                throw new PgpException("unknown key class");
            }

            this.publicPk = new PublicKeyPacket((byte)version, algorithm, time, bcpgKey);
            this.ids = new List<IUserDataPacket>();
            this.idSigs = new List<IList<PgpSignature>>();

            try
            {
                Init();
            }
            catch (IOException e)
            {
                throw new PgpException("exception calculating keyId", e);
            }
        }

        private static void RequireVersion4(int version, string algorithm)
        {
            if (version != PublicKeyPacket.Version4)
                throw new ArgumentException(algorithm + " cannot be used in version " + version + " keys");
        }

        public PgpPublicKey(PublicKeyPacket publicPk)
            : this(publicPk, new List<IUserDataPacket>(), new List<IList<PgpSignature>>())
        {
        }

        /// <summary>Constructor for a sub-key.</summary>
        internal PgpPublicKey(PublicKeyPacket publicPk, TrustPacket trustPk, IList<PgpSignature> sigs)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.subSigs = sigs;

            Init();
        }

        internal PgpPublicKey(
            PgpPublicKey	key,
            TrustPacket		trust,
            IList<PgpSignature> subSigs)
        {
            this.publicPk = key.publicPk;
            this.trustPk = trust;
            this.subSigs = subSigs;

            this.fingerprint = key.fingerprint;
            this.keyId = key.keyId;
            this.keyStrength = key.keyStrength;
            this.m_key = key.m_key;
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        internal PgpPublicKey(
            PgpPublicKey pubKey)
        {
            this.publicPk = pubKey.publicPk;

            this.keySigs = new List<PgpSignature>(pubKey.keySigs);
            this.ids = new List<IUserDataPacket>(pubKey.ids);
            this.idTrusts = new List<TrustPacket>(pubKey.idTrusts);

            this.idSigs = new List<IList<PgpSignature>>(pubKey.idSigs.Count);
            for (int i = 0; i < pubKey.idSigs.Count; ++i)
            {
                this.idSigs.Add(new List<PgpSignature>(pubKey.idSigs[i]));
            }

            if (pubKey.subSigs != null)
            {
                this.subSigs = new List<PgpSignature>(pubKey.subSigs);
            }

            this.fingerprint = pubKey.fingerprint;
            this.keyId = pubKey.keyId;
            this.keyStrength = pubKey.keyStrength;
            this.m_key = pubKey.m_key;
        }

        internal PgpPublicKey(
            PublicKeyPacket	publicPk,
            TrustPacket		trustPk,
            IList<PgpSignature> keySigs,
            IList<IUserDataPacket> ids,
            IList<TrustPacket> idTrusts,
            IList<IList<PgpSignature>> idSigs)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.keySigs = keySigs;
            this.ids = ids;
            this.idTrusts = idTrusts;
            this.idSigs = idSigs;

            Init();
        }

        internal PgpPublicKey(
            PublicKeyPacket	publicPk,
            IList<IUserDataPacket> ids,
            IList<IList<PgpSignature>> idSigs)
        {
            this.publicPk = publicPk;
            this.ids = ids;
            this.idSigs = idSigs;
            Init();
        }

        internal PgpPublicKey(
            PgpPublicKey original,
            TrustPacket trustPk,
            List<PgpSignature> keySigs,
            List<IUserDataPacket> ids,
            List<TrustPacket> idTrusts,
            IList<IList<PgpSignature>> idSigs)
        {
            this.publicPk = original.publicPk;
            this.fingerprint = original.fingerprint;
            this.keyStrength = original.keyStrength;
            this.keyId = original.keyId;
            this.m_key = original.m_key;

            this.trustPk = trustPk;
            this.keySigs = keySigs;
            this.ids = ids;
            this.idTrusts = idTrusts;
            this.idSigs = idSigs;
        }

        /// <summary>The version of this key.</summary>
        public int Version
        {
            get { return publicPk.Version; }
        }

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime
        {
            get { return publicPk.GetTime(); }
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public byte[] GetTrustData()
        {
            if (trustPk == null)
            {
                return null;
            }

            return Arrays.Clone(trustPk.GetLevelAndTrustAmount());
        }

        /// <summary>The number of valid seconds from creation time - zero means no expiry.</summary>
        /// <remarks>
        /// WARNING: for a subkey this value is derived from subkey binding signature packets that have
        /// NOT been cryptographically verified against the primary key, and for a version 4 primary key from
        /// self-signatures that have not been verified, so it must not be relied on as a security boundary - a
        /// forged, unverified signature packet can alter the result. When the expiry drives a trust decision, use
        /// <see cref="GetValidSeconds(PgpPublicKey)"/> (which verifies the signatures) or verify the signatures
        /// yourself. For a version 6 primary key only direct-key signatures that verify count (RFC 9580 5.2.3.10).
        /// </remarks>
        public long GetValidSeconds()
        {
            if (publicPk.Version <= 3)
            {
                return (long)publicPk.ValidDays * (24 * 60 * 60);
            }

            if (IsMasterKey)
            {
                long directKeySeconds = GetVersion6DirectKeyExpirationTime();
                if (directKeySeconds >= 0)
                    return directKeySeconds;

                for (int i = 0; i != MasterKeyCertificationTypes.Length; i++)
                {
                    long seconds = GetExpirationTimeFromSig(true, MasterKeyCertificationTypes[i]);
                    if (seconds >= 0)
                    {
                        return seconds;
                    }
                }
            }
            else
            {
                long seconds = GetExpirationTimeFromSig(false, PgpSignature.SubkeyBinding);
                if (seconds >= 0)
                {
                    return seconds;
                }

                seconds = GetExpirationTimeFromSig(false, PgpSignature.DirectKey);
                if (seconds >= 0)
                {
                    return seconds;
                }
            }

            return 0;
        }

        /// <summary>
        /// The number of valid seconds from creation time - zero means no expiry - deriving a subkey's
        /// expiry only from binding signatures that cryptographically verify against
        /// <paramref name="masterKey"/>.
        /// </summary>
        /// <remarks>
        /// Prefer this overload over <see cref="GetValidSeconds()"/> when the expiry of a subkey is used
        /// for a security decision: any binding signature packet that does not verify against the primary
        /// key is ignored, so an appended forged binding packet cannot influence the reported expiry.
        /// For a (v4+) master key the expiry comes from its newest self-signature that verifies and is in effect now,
        /// whatever its certification type (RFC 9580 5.2.3.10), and <paramref name="masterKey"/> is not consulted.
        /// Likewise only binding signatures in effect now count for a subkey.
        /// </remarks>
        /// <param name="masterKey">The primary key that binds this key; required when this is a subkey.</param>
        /// <exception cref="ArgumentNullException">If this is a subkey and <paramref name="masterKey"/> is null.
        /// </exception>
        public long GetValidSeconds(PgpPublicKey masterKey)
        {
            if (publicPk.Version <= 3)
            {
                return (long)publicPk.ValidDays * (24 * 60 * 60);
            }

            if (IsMasterKey)
            {
                // A master key's expiry comes from its newest self-signature that verifies and is in effect
                PgpSignature newest = GetNewestVerifiedSelfSignature(DateTime.UtcNow);
                return newest == null ? 0L : GetKeyExpirationTime(newest);
            }

            if (masterKey == null)
                throw new ArgumentNullException(nameof(masterKey));

            // Only subkey binding signatures that verify against the master key are trusted. The DirectKey
            // fallback used by GetValidSeconds() is intentionally omitted here: it is not the common path
            // and a DirectKey signature is not verifiable via VerifyCertification(masterKey, subKey).
            long bindingSeconds = GetVerifiedBindingExpirationTime(masterKey);
            if (bindingSeconds >= 0)
                return bindingSeconds;

            return 0;
        }

        private long GetVerifiedBindingExpirationTime(PgpPublicKey masterKey)
        {
            long expiryTime = -1L;
            long lastDate = -1L;

            foreach (PgpSignature sig in GetSignaturesOfType(PgpSignature.SubkeyBinding))
            {
                /*
                 * Trust only binding signatures that cryptographically verify against the master key. The
                 * signature's claimed issuer Key ID is not relied on (verification uses masterKey), so a
                 * forged packet cannot slip through by advertising any particular issuer.
                 */
                if (!IsInEffect(sig, DateTime.UtcNow) || !VerifyBindingSignature(sig, masterKey))
                    continue;

                /*
                 * RFC 4880 5.2.4.1: the most recent binding signature wins, even if it omits the Key
                 * Expiration Time subpacket (which removes any previously asserted expiry).
                 */
                long thisDate = sig.CreationTime.Ticks;
                if (thisDate > lastDate)
                {
                    lastDate = thisDate;

                    PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
                    expiryTime = hashed == null ? 0L : hashed.GetKeyExpirationTime();
                }
            }

            return expiryTime;
        }

        private bool VerifyBindingSignature(PgpSignature sig, PgpPublicKey masterKey)
        {
            try
            {
                sig.InitVerify(masterKey);

                return sig.VerifyCertification(masterKey, this);
            }
            catch (Exception)
            {
                // Any failure (malformed packet, unsupported/invalid signature, key mismatch) is treated
                // as "not verified" so a forged binding packet cannot influence the computed expiry.
                return false;
            }
        }

        /// <summary>
        /// The expiry of a version 6 primary key is kept in its direct-key signature (RFC 9580 10.1.1), and the
        /// newest one that verifies and is in effect wins (5.2.3.10). Returns -1 for other keys or if there is
        /// none.
        /// </summary>
        private long GetVersion6DirectKeyExpirationTime()
        {
            if (publicPk.Version != PublicKeyPacket.Version6)
                return -1L;

            PgpSignature newest = GetNewestVerifiedDirectKeySignature(DateTime.UtcNow);
            return newest == null ? -1L : GetKeyExpirationTime(newest);
        }

        /// <summary>
        /// The newest self-signature with the properties of the key that verifies and is in effect at the given
        /// time (RFC 9580 5.2.3.10): the direct-key signature of a version 6 key that has one, else the newest of
        /// the direct-key signatures and of the current certifications of the user IDs and user attributes that are
        /// not revoked, whatever their certification type. Null if there is none.
        /// </summary>
        private PgpSignature GetNewestVerifiedSelfSignature(DateTime at)
        {
            PgpSignature newest = GetNewestVerifiedDirectKeySignature(at);
            if (newest != null && publicPk.Version == PublicKeyPacket.Version6)
                return newest;

            // user attributes have self-signatures like user IDs (RFC 9580 5.12)
            for (int i = 0; i < ids.Count; ++i)
            {
                PgpSignature current = GetCurrentSelfCertification(idSigs[i], ids[i], at);
                if (current != null && IsNewerSelfSignature(current, newest))
                {
                    newest = current;
                }
            }
            return newest;
        }

        /// <summary>
        /// The current self-signature of a user ID or user attribute: its newest certification that verifies and is
        /// in effect, or null if there is none or a newer certification revocation retires the user ID. Such a
        /// revocation spares only the non-revocable certifications (RFC 9580 5.2.3.20), the newest of which then
        /// applies, without the properties of the newer certifications that it revokes.
        /// </summary>
        private PgpSignature GetCurrentSelfCertification(IEnumerable<PgpSignature> sigs, IUserDataPacket id,
            DateTime at)
        {
            PgpSignature certification = null, revocation = null;
            PgpSignature irrevocable = null;
            foreach (PgpSignature sig in sigs)
            {
                if (!IsSelfCertificationType(sig.SignatureType) || sig.KeyId != KeyId || !IsInEffect(sig, at) ||
                    !VerifySelfSignature(sig, id))
                {
                    continue;
                }

                if (sig.SignatureType == PgpSignature.CertificationRevocation)
                {
                    if (IsNewerSelfSignature(sig, revocation))
                    {
                        revocation = sig;
                    }
                    continue;
                }

                if (IsNewerSelfSignature(sig, certification))
                {
                    certification = sig;
                }
                if (sig.GetHashedSubPackets()?.IsRevocable() == false && IsNewerSelfSignature(sig, irrevocable))
                {
                    irrevocable = sig;
                }
            }

            bool revoked = revocation != null && IsNewerSelfSignature(revocation, certification);
            return revoked ? irrevocable : certification;
        }

        private PgpSignature GetNewestVerifiedDirectKeySignature(DateTime at)
        {
            PgpSignature newest = null;
            foreach (PgpSignature sig in GetSignaturesOfType(PgpSignature.DirectKey))
            {
                if (IsNewerSelfSignature(sig, newest) && IsInEffect(sig, at) && VerifySelfSignature(sig, null))
                {
                    newest = sig;
                }
            }
            return newest;
        }

        /// <summary>A certification of a user ID (0x10-0x13), or its revocation.</summary>
        private static bool IsSelfCertificationType(int signatureType) =>
            signatureType == PgpSignature.CertificationRevocation ||
            (signatureType >= PgpSignature.DefaultCertification && signatureType <= PgpSignature.PositiveCertification);

        /// <summary>Whether the signature is made by the given time, and not expired (RFC 9580 5.2.3.18).</summary>
        private static bool IsInEffect(PgpSignature sig, DateTime at)
        {
            if (sig.CreationTime > at)
                return false;

            long seconds = sig.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0L;
            return seconds <= 0 || sig.CreationTime.AddSeconds(seconds) > at;
        }

        /// <summary>
        /// The key expiration time of a self-signature or binding signature; the newest one wins even if it omits
        /// the Key Expiration Time, which removes the expiry.
        /// </summary>
        private static long GetKeyExpirationTime(PgpSignature sig)
        {
            PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
            return hashed == null ? 0L : hashed.GetKeyExpirationTime();
        }

        private bool IsNewerSelfSignature(PgpSignature sig, PgpSignature than) =>
            sig.KeyId == KeyId && (than == null || sig.CreationTime > than.CreationTime);

        /// <summary>
        /// Whether a direct-key signature (no user ID), or a certification of a user ID or user attribute, verifies.
        /// </summary>
        private bool VerifySelfSignature(PgpSignature sig, IUserDataPacket id)
        {
            try
            {
                sig.InitVerify(this);
                switch (id)
                {
                case null:
                    return sig.VerifyCertification(this);
                // the raw user ID, since the string of GetId() is not decoded as UTF-8
                case UserIdPacket userId:
                    return sig.VerifyCertification(userId.GetRawId(), this);
                case PgpUserAttributeSubpacketVector attributes:
                    return sig.VerifyCertification(attributes, this);
                default:
                    return false;
                }
            }
            catch (Exception)
            {
                // a self-signature that cannot be verified does not count
                return false;
            }
        }

        private long GetExpirationTimeFromSig(bool selfSigned, int signatureType)
        {
            long expiryTime = -1L;
            long lastDate = -1L;

            foreach (PgpSignature sig in GetSignaturesOfType(signatureType))
            {
                if (sig.KeyId == KeyId)
                {
                    /*
                     * RFC 4880 5.2.4.1: the most recent self-signature wins, even if it omits the Key Expiration Time
                     * subpacket (which removes any previously asserted expiry).
                     */
                    var thisDate = sig.CreationTime.Ticks;
                    if (thisDate > lastDate)
                    {
                        lastDate = thisDate;

                        PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
                        expiryTime = hashed == null ? 0L : hashed.GetKeyExpirationTime();
                    }
                }
                else if (!selfSigned)
                {
                    PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
                    if (hashed != null)
                    {
                        var keyExpireTime = hashed.GetSubpacket(SignatureSubpacketTag.KeyExpireTime);
                        if (keyExpireTime != null)
                        {
                            long current = ((KeyExpirationTime)keyExpireTime).Time;
                            if (current == 0 || current > expiryTime)
                            {
                                expiryTime = current;
                            }
                        }
                    }
                }
            }

            return expiryTime;
        }

        /// <summary>The Key ID associated with the public key.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => keyId;

        /// <summary>The fingerprint of the public key</summary>
        public byte[] GetFingerprint()
        {
            return (byte[]) fingerprint.Clone();
        }

        public bool HasFingerprint(byte[] fingerprint)
        {
            return Arrays.AreEqual(this.fingerprint, fingerprint);
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public bool IsEncryptionKey
        {
            get
            {
                switch (publicPk.Algorithm)
                {
                case PublicKeyAlgorithmTag.DiffieHellman:
                case PublicKeyAlgorithmTag.ECDH:
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                    return true;
                default:
                    return false;
                }
            }
        }

        /// <summary>True, if this could be a master key.</summary>
        public bool IsMasterKey
        {
            get
            {
                // this might seem a bit excessive, but we're also trying to flag something can't be a master key.
                return !(publicPk is PublicSubkeyPacket)
                    && !(this.IsEncryptionKey && publicPk.Algorithm != PublicKeyAlgorithmTag.RsaGeneral);
            }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return publicPk.Algorithm; }
        }

        /// <summary>The strength of the key in bits.</summary>
        /// <remarks>
        /// For RSA, DSA and ElGamal keys this is the size of the modulus, and for elliptic curve keys the size of the
        /// curve. The composite keys of RFC 9980 have the size of their elliptic curve, and SLH-DSA keys the size of
        /// their public key. It is 0 or -1 if it is not known.
        /// </remarks>
        public int BitStrength
        {
            get { return keyStrength; }
        }

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        public AsymmetricKeyParameter GetKey() =>
            m_key ?? (m_key = CreateKey());

        private AsymmetricKeyParameter CreateKey()
        {
            try
            {
                switch (publicPk.Algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    RsaPublicBcpgKey rsaK = (RsaPublicBcpgKey)publicPk.Key;
                    return new RsaKeyParameters(false, rsaK.Modulus, rsaK.PublicExponent);
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPublicBcpgKey dsaK = (DsaPublicBcpgKey)publicPk.Key;
                    return new DsaPublicKeyParameters(dsaK.Y, new DsaParameters(dsaK.P, dsaK.Q, dsaK.G));
                case PublicKeyAlgorithmTag.ECDsa:
                    ECDsaPublicBcpgKey ecdsaK = (ECDsaPublicBcpgKey)publicPk.Key;
                    return GetECKey("ECDSA", ecdsaK);
                case PublicKeyAlgorithmTag.ECDH:
                {
                    ECDHPublicBcpgKey ecdhK = (ECDHPublicBcpgKey)publicPk.Key;
                    var curveOid = ecdhK.CurveOid;

                    if (EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
                        CryptlibObjectIdentifiers.curvey25519.Equals(curveOid))
                    {
                        byte[] pEnc = BigIntegers.AsUnsignedByteArray(1 + X25519.PointSize, ecdhK.EncodedPoint);
                        if (pEnc[0] != 0x40)
                            throw new ArgumentException("Invalid X25519 public key");

                        return PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(curveOid),
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                            pEnc.AsSpan(1)));
#else
                            Arrays.CopyOfRange(pEnc, 1, pEnc.Length)));
#endif
                    }
                    else if (EdECObjectIdentifiers.id_X448.Equals(curveOid))
                    {
                        byte[] pEnc = BigIntegers.AsUnsignedByteArray(1 + X448.PointSize, ecdhK.EncodedPoint);
                        if (pEnc[0] != 0x40)
                            throw new ArgumentException("Invalid X448 public key");

                        return PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(curveOid),
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                            pEnc.AsSpan(1)));
#else
                            Arrays.CopyOfRange(pEnc, 1, pEnc.Length)));
#endif
                    }
                    else
                    {
                        return GetECKey("ECDH", ecdhK);
                    }
                }
                case PublicKeyAlgorithmTag.EdDsa_Legacy:
                {
                    EdDsaPublicBcpgKey eddsaK = (EdDsaPublicBcpgKey)publicPk.Key;
                    var curveOid = eddsaK.CurveOid;

                    if (EdECObjectIdentifiers.id_Ed25519.Equals(curveOid) ||
                        GnuObjectIdentifiers.Ed25519.Equals(curveOid))
                    {
                        byte[] pEnc = BigIntegers.AsUnsignedByteArray(1 + Ed25519.PublicKeySize, eddsaK.EncodedPoint);
                        if (pEnc[0] != 0x40)
                            throw new ArgumentException("Invalid Ed25519 public key");

                        return PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(curveOid),
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                            pEnc.AsSpan(1)));
#else
                            Arrays.CopyOfRange(pEnc, 1, pEnc.Length)));
#endif
                    }
                    else if (EdECObjectIdentifiers.id_Ed448.Equals(curveOid))
                    {
                        byte[] pEnc = BigIntegers.AsUnsignedByteArray(1 + Ed448.PublicKeySize, eddsaK.EncodedPoint);
                        if (pEnc[0] != 0x40)
                            throw new ArgumentException("Invalid Ed448 public key");

                        return PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(curveOid),
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                            pEnc.AsSpan(1)));
#else
                            Arrays.CopyOfRange(pEnc, 1, pEnc.Length)));
#endif
                    }
                    else 
                    {
                        throw new InvalidOperationException();
                    }
                }
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPublicBcpgKey elK = (ElGamalPublicBcpgKey)publicPk.Key;
                    return new ElGamalPublicKeyParameters(elK.Y, new ElGamalParameters(elK.P, elK.G));
                case PublicKeyAlgorithmTag.X25519:
                    return new X25519PublicKeyParameters(((X25519PublicBcpgKey)publicPk.Key).GetKey());
                case PublicKeyAlgorithmTag.X448:
                    return new X448PublicKeyParameters(((X448PublicBcpgKey)publicPk.Key).GetKey());
                case PublicKeyAlgorithmTag.Ed25519:
                    return new Ed25519PublicKeyParameters(((Ed25519PublicBcpgKey)publicPk.Key).GetKey());
                case PublicKeyAlgorithmTag.Ed448:
                    return new Ed448PublicKeyParameters(((Ed448PublicBcpgKey)publicPk.Key).GetKey());
                case PublicKeyAlgorithmTag.MLKem768_X25519:
                {
                    var mlKemX25519Key = (MLKem768X25519PublicBcpgKey)publicPk.Key;
                    return new MLKem768X25519PublicKeyParameters(
                        new X25519PublicKeyParameters(mlKemX25519Key.GetX25519PublicKey()),
                        MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768,
                            mlKemX25519Key.GetMLKemPublicKey()));
                }
                case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
                case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                    return SlhDsaPublicKeyParameters.FromEncoding(PgpUtilities.GetSlhDsaParameters(Algorithm),
                        ((SlhDsaPublicBcpgKey)publicPk.Key).GetKey());
                case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                {
                    var mlDsaKey = (MLDsa65Ed25519PublicBcpgKey)publicPk.Key;
                    return new MLDsa65Ed25519PublicKeyParameters(
                        new Ed25519PublicKeyParameters(mlDsaKey.GetEd25519PublicKey()),
                        MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, mlDsaKey.GetMLDsaPublicKey()));
                }
                case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                {
                    var mlDsaKey = (MLDsa87Ed448PublicBcpgKey)publicPk.Key;
                    return new MLDsa87Ed448PublicKeyParameters(
                        new Ed448PublicKeyParameters(mlDsaKey.GetEd448PublicKey()),
                        MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_87, mlDsaKey.GetMLDsaPublicKey()));
                }
                case PublicKeyAlgorithmTag.MLKem1024_X448:
                {
                    var mlKemX448Key = (MLKem1024X448PublicBcpgKey)publicPk.Key;
                    return new MLKem1024X448PublicKeyParameters(
                        new X448PublicKeyParameters(mlKemX448Key.GetX448PublicKey()),
                        MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024,
                            mlKemX448Key.GetMLKemPublicKey()));
                }
                default:
                    throw new PgpException("unknown public key algorithm encountered");
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception constructing public key", e);
            }
        }

        private ECPublicKeyParameters GetECKey(string algorithm, ECPublicBcpgKey ecK)
        {
            var parameters = ECNamedDomainParameters.LookupOid(ecK.CurveOid);

            BigInteger encodedPoint = ecK.EncodedPoint;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int encodedLength = BigIntegers.GetUnsignedByteLength(encodedPoint);
            Span<byte> encoding = encodedLength <= 512
                ? stackalloc byte[encodedLength]
                : new byte[encodedLength];
            BigIntegers.AsUnsignedByteArray(encodedPoint, encoding);
            ECPoint q = parameters.Curve.DecodePoint(encoding);
#else
            ECPoint q = parameters.Curve.DecodePoint(BigIntegers.AsUnsignedByteArray(encodedPoint));
#endif

            return new ECPublicKeyParameters(algorithm, q, parameters);
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <remarks>
        /// The user IDs are not decoded as UTF-8 (RFC 9580 5.11), so one with other than ASCII characters does not
        /// find its signatures again through <see cref="GetSignaturesForId(string)"/>; use
        /// <see cref="GetRawUserIds"/> with <see cref="GetSignaturesForId(byte[])"/> and
        /// <see cref="PgpSignature.VerifyCertification(byte[], PgpPublicKey)"/> instead.
        /// </remarks>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        // TODO[api] Decode the user IDs as UTF-8
        public IEnumerable<string> GetUserIds()
        {
            var result = new List<string>();

            foreach (var id in ids)
            {
                if (id is UserIdPacket userId)
                {
                    result.Add(userId.GetId());
                }
            }

            return CollectionUtilities.Proxy(result);
        }

        /// <summary>Return any userIDs associated with the key in raw byte form.</summary>
        /// <remarks>No attempt is made to convert the IDs into strings.</remarks>
        /// <returns>An <c>IEnumerable</c> of <c>byte[]</c>.</returns>
        public IEnumerable<byte[]> GetRawUserIds()
        {
            var result = new List<byte[]>();

            foreach (var id in ids)
            {
                if (id is UserIdPacket userId)
                {
                    result.Add(userId.GetRawId());
                }
            }

            return CollectionUtilities.Proxy(result);
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable<PgpUserAttributeSubpacketVector> GetUserAttributes()
        {
            var result = new List<PgpUserAttributeSubpacketVector>();

            foreach (var id in ids)
            {
                if (id is PgpUserAttributeSubpacketVector v)
                {
                    result.Add(v);
                }
            }

            return CollectionUtilities.Proxy(result);
        }

        /// <summary>Allows enumeration of any signatures associated with the passed in id.</summary>
        /// <param name="id">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForId(string id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            return GetSignaturesForId(new UserIdPacket(id));
        }

        public IEnumerable<PgpSignature> GetSignaturesForId(byte[] rawId)
        {
            if (rawId == null)
                throw new ArgumentNullException(nameof(rawId));

            return GetSignaturesForId(new UserIdPacket(rawId));
        }

        private IEnumerable<PgpSignature> GetSignaturesForId(UserIdPacket id)
        {
            var signatures = new List<PgpSignature>();
            bool userIdFound = false;

            for (int i = 0; i != ids.Count; i++)
            {
                if (id.Equals(ids[i]))
                {
                    userIdFound = true;
                    signatures.AddRange(idSigs[i]);
                }
            }

            return userIdFound ? signatures : null;
        }

        /// <summary>Return any signatures associated with the passed in key identifier keyID.</summary>
        /// <param name="keyID">the key id to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects issued by the key with keyID.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForKeyID(long keyID)
        {
            var sigs = new List<PgpSignature>();

            foreach (var sig in GetSignatures())
            {
                if (sig.KeyId == keyID)
                {
                    sigs.Add(sig);
                }
            }

            return CollectionUtilities.Proxy(sigs);
        }

        /// <summary>Allows enumeration of signatures associated with the passed in user attributes.</summary>
        /// <param name="userAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForUserAttribute(PgpUserAttributeSubpacketVector userAttributes)
        {
            if (userAttributes == null)
                throw new ArgumentNullException(nameof(userAttributes));

            var result = new List<PgpSignature>();
            bool attributeFound = false;

            for (int i = 0; i != ids.Count; i++)
            {
                if (userAttributes.Equals(ids[i]))
                {
                    attributeFound = true;
                    result.AddRange(idSigs[i]);
                }
            }

            return attributeFound ? CollectionUtilities.Proxy(result) : null;
        }

        /// <summary>Allows enumeration of signatures of the passed in type that are on this key.</summary>
        /// <param name="signatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesOfType(int signatureType)
        {
            var result = new List<PgpSignature>();

            foreach (PgpSignature sig in GetSignatures())
            {
                if (sig.SignatureType == signatureType)
                {
                    result.Add(sig);
                }
            }

            return CollectionUtilities.Proxy(result);
        }

        /// <summary>Allows enumeration of all signatures/certifications associated with this key.</summary>
        /// <returns>An <c>IEnumerable</c> with all signatures/certifications.</returns>
        public IEnumerable<PgpSignature> GetSignatures()
        {
            var result = subSigs;
            if (result == null)
            {
                var temp = new List<PgpSignature>(keySigs);

                foreach (var extraSigs in idSigs)
                {
                    temp.AddRange(extraSigs);
                }

                result = temp;
            }

            return CollectionUtilities.Proxy(result);
        }

        /**
         * Return all signatures/certifications directly associated with this key (ie, not to a user id).
         *
         * @return an iterator (possibly empty) with all signatures/certifications.
         */
        public IEnumerable<PgpSignature> GetKeySignatures()
        {
            var result = subSigs ?? new List<PgpSignature>(keySigs);

            return CollectionUtilities.Proxy(result);
        }

        public PublicKeyPacket PublicKeyPacket
        {
            get { return publicPk; }
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(Stream outStr)
        {
            Encode(outStr, false);
        }

        /**
         * Encode the key to outStream, with trust packets stripped out if forTransfer is true.
         *
         * @param outStream   stream to write the key encoding to.
         * @param forTransfer if the purpose of encoding is to send key to other users.
         * @throws IOException in case of encoding error.
         */
        public void Encode(Stream outStr, bool forTransfer)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStr);

            publicPk.Encode(bcpgOut);

            if (!forTransfer)
            {
                trustPk?.Encode(bcpgOut);
            }

            if (subSigs == null)    // not a sub-key
            {
                foreach (PgpSignature keySig in keySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (int i = 0; i != ids.Count; i++)
                {
                    if (ids[i] is UserIdPacket id)
                    {
                        id.Encode(bcpgOut);
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)ids[i];
                        new UserAttributePacket(v.ToSubpacketArray()).Encode(bcpgOut);
                    }

                    if (!forTransfer)
                    {
                        idTrusts[i]?.Encode(bcpgOut);
                    }

                    foreach (PgpSignature sig in idSigs[i])
                    {
                        sig.Encode(bcpgOut, forTransfer);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in subSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }
        }

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <remarks>This method is poorly named (misleading); use <see cref="HasRevocation"/> instead.</remarks>
        /// <returns><c>true</c>, if this (sub)key has had a (possibly invalid) revocation attached.</returns>
        [Obsolete("Use 'HasRevocation' instead")]
        public bool IsRevoked() => HasRevocation();

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <remarks>
        /// WARNING: this reports only whether a revocation-type signature packet is <em>present</em>; the packet is NOT
        /// cryptographically verified, so for a key obtained from an untrusted source neither result is an
        /// authenticated trust signal.
        /// </remarks>
        /// <returns>True, if a revocation signature (verified or not) is present on this (sub)key.</returns>
        public bool HasRevocation()
        {
            int ns = 0;
            bool revoked = false;

            // subSigs is null for a primary key and non-null for a subkey; it is the reliable discriminator here
            // (isMasterKey can be false for an encryption-algorithm primary, whose subSigs would be null, which
            // previously threw a NullPointerException).
            if (subSigs == null)    // Primary key
            {
                while (!revoked && (ns < keySigs.Count))
                {
                    if (keySigs[ns++].SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else                    // Sub-key
            {
                while (!revoked && (ns < subSigs.Count))
                {
                    if (subSigs[ns++].SignatureType == PgpSignature.SubkeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            return revoked;
        }

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey	key,
            string			id,
            PgpSignature	certification)
        {
            return AddCert(key, new UserIdPacket(id), certification);
        }

        internal static PgpPublicKey AddRawIdCertification(PgpPublicKey key, byte[] rawId,
            PgpSignature certification) =>
            AddCert(key, new UserIdPacket(rawId), certification);

        /// <summary>Add a certification for the given UserAttributeSubpackets to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="userAttributes">The attributes the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey					key,
            PgpUserAttributeSubpacketVector	userAttributes,
            PgpSignature					certification)
        {
            return AddCert(key, userAttributes, certification);
        }

        private static PgpPublicKey AddCert(
            PgpPublicKey	key,
            IUserDataPacket id,
            PgpSignature	certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            IList<PgpSignature> sigList = null;

            for (int i = 0; i != returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    sigList = returnKey.idSigs[i];
                }
            }

            if (sigList != null)
            {
                sigList.Add(certification);
            }
            else
            {
                sigList = new List<PgpSignature>();
                sigList.Add(certification);
                returnKey.ids.Add(id);
                returnKey.idTrusts.Add(null);
                returnKey.idSigs.Add(sigList);
            }

            return returnKey;
        }

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey key,
            PgpUserAttributeSubpacketVector	userAttributes)
        {
            return RemoveCert(key, userAttributes);
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey	key, string id)
        {
            return RemoveCert(key, new UserIdPacket(id));
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="rawId">The ID that is to be removed in raw byte form.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey key, byte[] rawId)
        {
            return RemoveCert(key, new UserIdPacket(rawId));
        }

        private static PgpPublicKey RemoveCert(PgpPublicKey	key, IUserDataPacket id)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = returnKey.ids.Count - 1; i >= 0; i--)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    found = true;
                    returnKey.ids.RemoveAt(i);
                    returnKey.idTrusts.RemoveAt(i);
                    returnKey.idSigs.RemoveAt(i);
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from (in its raw byte form).</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey key, byte[] id, PgpSignature certification)
        {
            return RemoveCert(key, new UserIdPacket(id), certification);
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey	key, string id, PgpSignature certification)
        {
            return RemoveCert(key, new UserIdPacket(id), certification);
        }

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey key, PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return RemoveCert(key, userAttributes, certification);
        }

        private static PgpPublicKey RemoveCert(PgpPublicKey	key, IUserDataPacket id, PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = returnKey.ids.Count - 1; i >= 0 ; i--)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    found |= returnKey.idSigs[i].Remove(certification);
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="key">The key the revocation is to be added to.</param>
        /// <param name="certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static PgpPublicKey AddCertification(PgpPublicKey key, PgpSignature certification)
        {
            if (key.IsMasterKey)
            {
                if (certification.SignatureType == PgpSignature.SubkeyRevocation)
                    throw new ArgumentException("signature type incorrect for master key revocation.");
            }
            else
            {
                if (certification.SignatureType == PgpSignature.KeyRevocation)
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
            }

            PgpPublicKey returnKey = new PgpPublicKey(key);
            var sigs = returnKey.subSigs ?? returnKey.keySigs;

            sigs.Add(certification);

            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(PgpPublicKey	key, PgpSignature certification)
        {
            var returnKey = new PgpPublicKey(key);
            var sigs = returnKey.subSigs ?? returnKey.keySigs;

            bool found = sigs.Remove(certification);

            foreach (var idSigs in returnKey.idSigs)
            {
                found |= idSigs.Remove(certification);
            }

            return found ? returnKey : null;
        }

        /// <summary>
        /// Merge the given local public key with another, potentially fresher copy. The resulting public key
        /// contains the sum of both keys' user-ids and signatures.
        /// </summary>
        /// <remarks>
        /// If joinTrustPackets is set to true and the copy carries a trust packet, the joined key will copy the
        /// trust-packet from the copy. Otherwise, it will carry the trust packet of the local key.
        /// </remarks>
        /// <param name="key">local public key.</param>
        /// <param name="copy">copy of the public key (e.g. from a key server).</param>
        /// <param name="joinTrustPackets">if true, trust packets from the copy are copied over into the resulting key.
        /// </param>
        /// <param name="allowSubkeySigsOnNonSubkey">if true, subkey signatures on the copy will be present in the
        /// merged key, even if key was not a subkey before.</param>
        /// <returns>joined key.</returns>
        public static PgpPublicKey Join(PgpPublicKey key, PgpPublicKey copy, bool joinTrustPackets,
            bool allowSubkeySigsOnNonSubkey)
        {
            if (key.KeyId != copy.keyId)
                throw new ArgumentException("Key-ID mismatch.");

            TrustPacket trustPk = key.trustPk;
            List<PgpSignature> keySigs = new List<PgpSignature>(key.keySigs);
            List<IUserDataPacket> ids = new List<IUserDataPacket>(key.ids);
            List<TrustPacket> idTrusts = new List<TrustPacket>(key.idTrusts);
            List<IList<PgpSignature>> idSigs = new List<IList<PgpSignature>>(key.idSigs);
            List<PgpSignature> subSigs = key.subSigs == null ? null : new List<PgpSignature>(key.subSigs);

            if (joinTrustPackets)
            {
                if (copy.trustPk != null)
                {
                    trustPk = copy.trustPk;
                }
            }

            // key signatures
            foreach (PgpSignature keySig in copy.keySigs)
            {
                bool found = false;
                for (int i = 0; i < keySigs.Count; i++)
                {
                    PgpSignature existingKeySig = keySigs[i];
                    if (PgpSignature.IsSignatureEncodingEqual(existingKeySig, keySig))
                    {
                        found = true;
                        // join existing sig with copy to apply modifications in unhashed subpackets
                        existingKeySig = PgpSignature.Join(existingKeySig, keySig);
                        keySigs[i] = existingKeySig;
                        break;
                    }
                }
                if (found)
                    break;

                keySigs.Add(keySig);
            }

            // user-ids and id sigs
            for (int idIdx = 0; idIdx < copy.ids.Count; idIdx++)
            {
                IUserDataPacket copyId = copy.ids[idIdx];
                List<PgpSignature> copyIdSigs = new List<PgpSignature>(copy.idSigs[idIdx]);
                TrustPacket copyTrust = copy.idTrusts[idIdx];

                int existingIdIndex = -1;
                for (int i = 0; i < ids.Count; i++)
                {
                    IUserDataPacket existingId = ids[i];
                    if (existingId.Equals(copyId))
                    {
                        existingIdIndex = i;
                        break;
                    }
                }

                // new user-id
                if (existingIdIndex == -1)
                {
                    ids.Add(copyId);
                    idSigs.Add(copyIdSigs);
                    idTrusts.Add(joinTrustPackets ? copyTrust : null);
                    continue;
                }

                // existing user-id
                if (joinTrustPackets && copyTrust != null)
                {
                    TrustPacket existingTrust = idTrusts[existingIdIndex];
                    if (existingTrust == null ||
                        Arrays.AreEqual(copyTrust.GetLevelAndTrustAmount(), existingTrust.GetLevelAndTrustAmount()))
                    {
                        idTrusts[existingIdIndex] = copyTrust;
                    }
                }

                var existingIdSigs = idSigs[existingIdIndex];
                foreach (PgpSignature newSig in copyIdSigs)
                {
                    bool found = false;
                    for (int i = 0; i < existingIdSigs.Count; i++)
                    {
                        PgpSignature existingSig = existingIdSigs[i];
                        if (PgpSignature.IsSignatureEncodingEqual(newSig, existingSig))
                        {
                            found = true;
                            // join existing sig with copy to apply modifications in unhashed subpackets
                            existingSig = PgpSignature.Join(existingSig, newSig);
                            existingIdSigs[i] = existingSig;
                            break;
                        }
                    }
                    if (!found)
                    {
                        existingIdSigs.Add(newSig);
                    }
                }
            }

            // subSigs
            if (copy.subSigs != null)
            {
                if (subSigs == null && allowSubkeySigsOnNonSubkey)
                {
                    subSigs = new List<PgpSignature>(copy.subSigs);
                }
                else
                {
                    foreach (PgpSignature copySubSig in copy.subSigs)
                    {
                        bool found = false;
                        for (int i = 0; subSigs != null && i < subSigs.Count; i++)
                        {
                            PgpSignature existingSubSig = subSigs[i];
                            if (PgpSignature.IsSignatureEncodingEqual(existingSubSig, copySubSig))
                            {
                                found = true;
                                // join existing sig with copy to apply modifications in unhashed subpackets
                                existingSubSig = PgpSignature.Join(existingSubSig, copySubSig);
                                subSigs[i] = existingSubSig;
                                break;
                            }
                        }
                        if (!found && subSigs != null)
                        {
                            subSigs.Add(copySubSig);
                        }
                    }
                }
            }

            PgpPublicKey merged = new PgpPublicKey(key, trustPk, keySigs, ids, idTrusts, idSigs);
            merged.subSigs = subSigs;

            return merged;
        }
    }
}
