using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;

using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
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
        private const byte v4FingerprintPreamble = 0x99;
        private const byte v5FingerprintPreamble = 0x9A;
        private const byte v6FingerprintPreamble = 0x9B;

        internal static byte FingerprintPreamble(int version)
        {
            switch (version)
            {
                case PublicKeyPacket.Version4:
                    return v4FingerprintPreamble;
                case PublicKeyPacket.Version5:
                    return v5FingerprintPreamble;
                case PublicKeyPacket.Version6:
                    return v6FingerprintPreamble;
                default:
                    throw new PgpException($"unsupported OpenPGP key packet version: {version}");
            }
        }
        private static IDigest CreateDigestForFingerprint(int version)
        {
            switch (version)
            {
                case PublicKeyPacket.Version2:
                case PublicKeyPacket.Version3:
                    return PgpUtilities.CreateDigest(HashAlgorithmTag.MD5);
                case PublicKeyPacket.Version4:
                    return PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);
                case PublicKeyPacket.Version5:
                case PublicKeyPacket.Version6:
                    return PgpUtilities.CreateDigest(HashAlgorithmTag.Sha256);
                default:
                    throw new PgpException($"unsupported OpenPGP key packet version: {version}");
            }
        }

        // We default to these as they are specified as mandatory in RFC 6631.
        private static readonly PgpKdfParameters DefaultKdfParameters = new PgpKdfParameters(HashAlgorithmTag.Sha256,
            SymmetricKeyAlgorithmTag.Aes128);

        public static byte[] CalculateFingerprint(PublicKeyPacket publicPk)
        {
            IBcpgKey key = publicPk.Key;
            IDigest digest = CreateDigestForFingerprint(publicPk.Version);

            if (publicPk.Version <= PublicKeyPacket.Version3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;

                try
                {
                    UpdateDigest(digest, rK.Modulus);
                    UpdateDigest(digest, rK.PublicExponent);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
            else
            {
                try
                {
                    digest.Update(FingerprintPreamble(publicPk.Version));

                    byte[] kBytes = publicPk.GetEncodedContents();

                    if (publicPk.Version == PublicKeyPacket.Version4)
                    {
                        digest.Update((byte)(kBytes.Length >> 8));
                        digest.Update((byte)kBytes.Length);
                    }
                    else if (publicPk.Version == PublicKeyPacket.Version5 || publicPk.Version == PublicKeyPacket.Version6)
                    {
                        digest.Update((byte)(kBytes.Length >> 24));
                        digest.Update((byte)(kBytes.Length >> 16));
                        digest.Update((byte)(kBytes.Length >> 8));
                        digest.Update((byte)kBytes.Length);
                    }
                    else
                    {
                        throw new PgpException($"unsupported OpenPGP key packet version: {publicPk.Version}");
                    }

                    digest.BlockUpdate(kBytes, 0, kBytes.Length);
                }
                catch (Exception e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
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

        private void Init()
        {
            IBcpgKey key = publicPk.Key;

            this.fingerprint = CalculateFingerprint(publicPk);

            if (publicPk.Version <= PublicKeyPacket.Version3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey) key;

                this.keyId = rK.Modulus.LongValue;
                this.keyStrength = rK.Modulus.BitLength;
            }
            else
            {
                if (publicPk.Version == PublicKeyPacket.Version4)
                {
                    this.keyId = (long)Pack.BE_To_UInt64(fingerprint, fingerprint.Length - 8);
                }
                else
                {
                    this.keyId = (long)Pack.BE_To_UInt64(fingerprint);
                }

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
                    X9ECParametersHolder ecParameters = ECKeyPairGenerator.FindECCurveByOidLazy(curveOid);

                    if (ecParameters != null)
                    {
                        this.keyStrength = ecParameters.Curve.FieldSize;
                    }
                    else
                    {
                        this.keyStrength = -1; // unknown
                    }
                }
            }
        }


        public PgpPublicKey(PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey, DateTime time)
            :this(PublicKeyPacket.DefaultVersion, algorithm, pubKey, time)
        {
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
        public PgpPublicKey(int version, PublicKeyAlgorithmTag algorithm, AsymmetricKeyParameter pubKey, DateTime time)
        {
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected a public key", nameof(pubKey));

            IBcpgKey bcpgKey;
            if (pubKey is RsaKeyParameters rK)
            {
                bcpgKey = new RsaPublicBcpgKey(rK.Modulus, rK.Exponent);
            }
            else if (pubKey is DsaPublicKeyParameters dK)
            {
                DsaParameters dP = dK.Parameters;

                bcpgKey = new DsaPublicBcpgKey(dP.P, dP.Q, dP.G, dK.Y);
            }
            else if (pubKey is ElGamalPublicKeyParameters eK)
            {
                ElGamalParameters eS = eK.Parameters;

                bcpgKey = new ElGamalPublicBcpgKey(eS.P, eS.G, eK.Y);
            }
            else if (pubKey is ECPublicKeyParameters ecK)
            {
                if (algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    bcpgKey = new ECDHPublicBcpgKey(ecK.PublicKeyParamSet, ecK.Q, HashAlgorithmTag.Sha256,
                        SymmetricKeyAlgorithmTag.Aes128);
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
                else
                {
                    byte[] pointEnc = new byte[1 + Ed25519PublicKeyParameters.KeySize];
                    pointEnc[0] = 0x40;
                    ed25519PubKey.Encode(pointEnc, 1);
                    bcpgKey = new EdDsaPublicBcpgKey(GnuObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
                }
            }
            else if (pubKey is Ed448PublicKeyParameters ed448PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.Ed448)
                {
                    bcpgKey = new Ed448PublicBcpgKey(ed448PubKey.GetEncoded());
                }
                else
                {
                    byte[] pointEnc = new byte[Ed448PublicKeyParameters.KeySize];
                    ed448PubKey.Encode(pointEnc, 0);
                    bcpgKey = new EdDsaPublicBcpgKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, pointEnc));
                }
            }
            else if (pubKey is X25519PublicKeyParameters x25519PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.X25519)
                {
                    bcpgKey = new X25519PublicBcpgKey(x25519PubKey.GetEncoded());
                }
                else
                {
                    byte[] pointEnc = new byte[1 + X25519PublicKeyParameters.KeySize];
                    pointEnc[0] = 0x40;
                    x25519PubKey.Encode(pointEnc, 1);

                    PgpKdfParameters kdfParams = DefaultKdfParameters;

                    bcpgKey = new ECDHPublicBcpgKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, pointEnc),
                        kdfParams.HashAlgorithm, kdfParams.SymmetricWrapAlgorithm);
                }
            }
            else if (pubKey is X448PublicKeyParameters x448PubKey)
            {
                if (algorithm == PublicKeyAlgorithmTag.X448)
                {
                    bcpgKey = new X448PublicBcpgKey(x448PubKey.GetEncoded());
                }
                else
                {
                    byte[] pointEnc = new byte[X448PublicKeyParameters.KeySize];
                    x448PubKey.Encode(pointEnc, 0);

                    PgpKdfParameters kdfParams = DefaultKdfParameters;

                    bcpgKey = new ECDHPublicBcpgKey(EdECObjectIdentifiers.id_X448, new BigInteger(1, pointEnc),
                        kdfParams.HashAlgorithm, kdfParams.SymmetricWrapAlgorithm);
                }
            }
            else
            {
                throw new PgpException("unknown key class");
            }

            this.publicPk = new PublicKeyPacket(version, algorithm, time, bcpgKey);
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
        public long GetValidSeconds()
        {
            if (publicPk.Version <= PublicKeyPacket.Version3)
            {
                return (long)publicPk.ValidDays * (24 * 60 * 60);
            }

            if (IsMasterKey)
            {
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

        private long GetExpirationTimeFromSig(bool selfSigned, int signatureType)
        {
            long expiryTime = -1;
            long lastDate = -1;

            foreach (PgpSignature sig in GetSignaturesOfType(signatureType))
            {
                if (selfSigned && sig.KeyId != this.KeyId)
                    continue;

                PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
                if (hashed == null)
                    continue;

                if (!hashed.HasSubpacket(SignatureSubpacketTag.KeyExpireTime))
                    continue;

                long current = hashed.GetKeyExpirationTime();

                if (sig.KeyId == this.KeyId)
                {
                    if (sig.CreationTime.Ticks > lastDate)
                    {
                        lastDate = sig.CreationTime.Ticks;
                        expiryTime = current;
                    }
                }
                else if (current == 0 || current > expiryTime)
                {
                    expiryTime = current;
                }
            }

            return expiryTime;
        }

        /// <summary>The key ID associated with the public key.</summary>
        public long KeyId
        {
            get { return keyId; }
        }

        /// <summary>The fingerprint of the public key</summary>
        public byte[] GetFingerprint()
        {
            return Arrays.Clone(fingerprint);
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
                    case PublicKeyAlgorithmTag.ECDH:
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.X25519:
                    case PublicKeyAlgorithmTag.X448:
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
        public int BitStrength
        {
            get { return keyStrength; }
        }

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        public AsymmetricKeyParameter GetKey()
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

                case PublicKeyAlgorithmTag.Ed25519:
                    Ed25519PublicBcpgKey ed25519key = (Ed25519PublicBcpgKey)publicPk.Key;
                    return new Ed25519PublicKeyParameters(ed25519key.GetKey());

                case PublicKeyAlgorithmTag.X25519:
                    X25519PublicBcpgKey x25519key = (X25519PublicBcpgKey)publicPk.Key;
                    return new X25519PublicKeyParameters(x25519key.GetKey());

                case PublicKeyAlgorithmTag.Ed448:
                    Ed448PublicBcpgKey ed448key = (Ed448PublicBcpgKey)publicPk.Key;
                    return new Ed448PublicKeyParameters(ed448key.GetKey());

                case PublicKeyAlgorithmTag.X448:
                    X448PublicBcpgKey x448key = (X448PublicBcpgKey)publicPk.Key;
                    return new X448PublicKeyParameters(x448key.GetKey());

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
            X9ECParameters x9 = ECKeyPairGenerator.FindECCurveByOid(ecK.CurveOid);
            BigInteger encodedPoint = ecK.EncodedPoint;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int encodedLength = BigIntegers.GetUnsignedByteLength(encodedPoint);
            Span<byte> encoding = encodedLength <= 512
                ? stackalloc byte[encodedLength]
                : new byte[encodedLength];
            BigIntegers.AsUnsignedByteArray(encodedPoint, encoding);
            ECPoint q = x9.Curve.DecodePoint(encoding);
#else
            ECPoint q = x9.Curve.DecodePoint(BigIntegers.AsUnsignedByteArray(encodedPoint));
#endif

            return new ECPublicKeyParameters(algorithm, q, ecK.CurveOid);
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
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

            bcpgOut.WritePacket(publicPk);
            if (!forTransfer && trustPk != null)
            {
                bcpgOut.WritePacket(trustPk);
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
                        bcpgOut.WritePacket(id);
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)ids[i];
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (!forTransfer && idTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((TrustPacket)idTrusts[i]);
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
        /// <returns>True, if this (sub)key has been revoked.</returns>
        public bool IsRevoked()
        {
            int ns = 0;
            bool revoked = false;
            if (IsMasterKey)	// Master key
            {
                while (!revoked && (ns < keySigs.Count))
                {
                    if (((PgpSignature)keySigs[ns++]).SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else	// Sub-key
            {
                while (!revoked && (ns < subSigs.Count))
                {
                    if (((PgpSignature)subSigs[ns++]).SignatureType == PgpSignature.SubkeyRevocation)
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

            for (int i = 0; i < returnKey.ids.Count; i++)
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

            for (int i = 0; i < returnKey.ids.Count; i++)
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