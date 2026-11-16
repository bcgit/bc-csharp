using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>Signer for RSA signatures, hashing the message with a digest before signing.</summary>
    public class RsaDigestSigner
        : ISigner
    {
        private readonly IAsymmetricBlockCipher m_engine;
        private readonly AlgorithmIdentifier m_digestAlgID;
        private readonly IDigest m_digest;
        private bool m_forSigning;

        private static readonly IDictionary<string, DerObjectIdentifier> OidMap =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Load oid table.
        /// </summary>
        static RsaDigestSigner()
        {
            OidMap["RIPEMD128"] = TeleTrusTObjectIdentifiers.RipeMD128;
            OidMap["RIPEMD160"] = TeleTrusTObjectIdentifiers.RipeMD160;
            OidMap["RIPEMD256"] = TeleTrusTObjectIdentifiers.RipeMD256;

            OidMap["SHA-1"] = X509ObjectIdentifiers.IdSha1;
            OidMap["SHA-224"] = NistObjectIdentifiers.IdSha224;
            OidMap["SHA-256"] = NistObjectIdentifiers.IdSha256;
            OidMap["SHA-384"] = NistObjectIdentifiers.IdSha384;
            OidMap["SHA-512"] = NistObjectIdentifiers.IdSha512;
            OidMap["SHA-512/224"] = NistObjectIdentifiers.IdSha512_224;
            OidMap["SHA-512/256"] = NistObjectIdentifiers.IdSha512_256;
            OidMap["SHA3-224"] = NistObjectIdentifiers.IdSha3_224;
            OidMap["SHA3-256"] = NistObjectIdentifiers.IdSha3_256;
            OidMap["SHA3-384"] = NistObjectIdentifiers.IdSha3_384;
            OidMap["SHA3-512"] = NistObjectIdentifiers.IdSha3_512;

            OidMap["MD2"] = PkcsObjectIdentifiers.MD2;
            OidMap["MD4"] = PkcsObjectIdentifiers.MD4;
            OidMap["MD5"] = PkcsObjectIdentifiers.MD5;
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="digest">The digest.</param>
        public RsaDigestSigner(IDigest digest)
            :   this(digest, CollectionUtilities.GetValueOrNull(OidMap, digest.AlgorithmName))
        {
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="digest">The digest.</param>
        /// <param name="digestOid">The digest oid.</param>
        public RsaDigestSigner(IDigest digest, DerObjectIdentifier digestOid)
            :   this(digest, new AlgorithmIdentifier(digestOid, DerNull.Instance))
        {
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="digest">The digest.</param>
        /// <param name="algId">The alg id.</param>
        // TODO[api] Rename 'algId' to 'digestAlgID'
        public RsaDigestSigner(IDigest digest, AlgorithmIdentifier algId)
            :   this(new RsaCoreEngine(), digest, algId)
        {
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="rsa">The rsa.</param>
        /// <param name="digest">The digest.</param>
        /// <param name="digestOid">The digest oid.</param>
        public RsaDigestSigner(IRsa rsa, IDigest digest, DerObjectIdentifier digestOid)
            :   this(rsa, digest, new AlgorithmIdentifier(digestOid, DerNull.Instance))
        {
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="rsa">The rsa.</param>
        /// <param name="digest">The digest.</param>
        /// <param name="algId">The alg id.</param>
        // TODO[api] Rename 'algId' to 'digestAlgID'
        public RsaDigestSigner(IRsa rsa, IDigest digest, AlgorithmIdentifier algId)
            :   this(new RsaBlindedEngine(rsa), digest, algId)
        {
        }

        /// <summary>Create a new <see cref="RsaDigestSigner"/>.</summary>
        /// <param name="rsaEngine">The rsa engine.</param>
        /// <param name="digest">The digest.</param>
        /// <param name="algId">The alg id.</param>
        // TODO[api] Rename 'algId' to 'digestAlgID'
        public RsaDigestSigner(IAsymmetricBlockCipher rsaEngine, IDigest digest, AlgorithmIdentifier algId)
        {
            m_engine = new Pkcs1Encoding(rsaEngine);
            m_digest = digest;
            m_digestAlgID = algId;
        }

        /// <inheritdoc/>
        public virtual string AlgorithmName => m_digest.AlgorithmName + "withRSA";

        /**
         * Initialise the signer for signing or verification.
         *
         * @param forSigning true if for signing, false otherwise
         * @param param necessary parameters.
         */
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            m_forSigning = forSigning;

            var key = (AsymmetricKeyParameter)ParameterUtilities.IgnoreRandom(parameters);

            if (forSigning && !key.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            if (!forSigning && key.IsPrivate)
                throw new InvalidKeyException("Verification requires public key.");

            Reset();

            m_engine.Init(forSigning, parameters);
        }

        /// <inheritdoc/>
        public virtual void Update(byte input) => m_digest.Update(input);

        /// <inheritdoc/>
        public virtual void BlockUpdate(byte[] input, int inOff, int inLen) =>
            m_digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual void BlockUpdate(ReadOnlySpan<byte> input) => m_digest.BlockUpdate(input);
#endif

        /// <inheritdoc/>
        public virtual int GetMaxSignatureSize() => m_engine.GetOutputBlockSize();

        /// <inheritdoc/>
        public virtual byte[] GenerateSignature()
        {
            if (!m_forSigning)
                throw new InvalidOperationException("RsaDigestSigner not initialised for signature generation.");

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            try
            {
                byte[] data;
                if (m_digestAlgID == null)
                {
                    data = CheckDerEncoded(hash);
                }
                else
                {
                    data = DerEncode(m_digestAlgID, hash);
                }

                return m_engine.ProcessBlock(data, 0, data.Length);
            }
            catch (Exception e) when (!(e is CryptoException))
            {
                throw new CryptoException("unable to encode signature: " + e.Message, e);
            }
        }

        /// <inheritdoc/>
        public virtual bool VerifySignature(byte[] signature)
        {
            if (m_forSigning)
                throw new InvalidOperationException("RsaDigestSigner not initialised for verification");

            byte[] sig;
            try
            {
                sig = m_engine.ProcessBlock(signature, 0, signature.Length);
            }
            catch (Exception)
            {
                return false;
            }

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            if (m_digestAlgID == null)
                return Arrays.FixedTimeEquals(sig, CheckDerEncoded(hash));

            if (Arrays.FixedTimeEquals(sig, DerEncode(m_digestAlgID, hash)))
                return true;

            if (TryGetAltAlgID(m_digestAlgID, out var altAlgID))
            {
                if (Arrays.FixedTimeEquals(sig, DerEncode(altAlgID, hash)))
                    return true;
            }

            return false;
        }

        /// <inheritdoc/>
        public virtual void Reset() => m_digest.Reset();

        private static byte[] CheckDerEncoded(byte[] hash)
        {
            DigestInfo.GetInstance(hash);
            return hash;
        }

        private static byte[] DerEncode(AlgorithmIdentifier digestAlgID, byte[] hash) =>
            new DigestInfo(digestAlgID, DerOctetString.WithContents(hash)).GetEncoded(Asn1Encodable.Der);

        private static bool TryGetAltAlgID(AlgorithmIdentifier algID, out AlgorithmIdentifier altAlgID)
        {
            var parameters = algID.Parameters;
            if (parameters == null)
            {
                altAlgID = new AlgorithmIdentifier(algID.Algorithm, DerNull.Instance);
            }
            else if (DerNull.Instance.Equals(parameters))
            {
                altAlgID = new AlgorithmIdentifier(algID.Algorithm, null);
            }
            else
            {
                altAlgID = default;
                return false;
            }
            return true;
        }
    }
}
