using System;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A one pass signature object.</summary>
    public class PgpOnePassSignature
    {
        private static OnePassSignaturePacket Cast(Packet packet)
        {
            if (packet is OnePassSignaturePacket onePassSignaturePacket)
                return onePassSignaturePacket;

            throw new IOException("unexpected packet in stream: " + packet);
        }

        private readonly OnePassSignaturePacket sigPack;
        private readonly int signatureType;

        private ISigner sig;
        private byte lastb;

        // see PgpSignature
        private IDigest m_prefixDigest;
        private bool m_unusable;

        internal PgpOnePassSignature(BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

        internal PgpOnePassSignature(OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
            this.signatureType = sigPack.SignatureType;
        }

        /// <summary>Initialise the signature object for verification.</summary>
        public void InitVerify(PgpPublicKey pubKey)
        {
            lastb = 0;
            m_prefixDigest = null;

            // RFC 9580 5.4: a version 6 one-pass signature goes with a version 6 key (and the other way around), and
            // announces the fingerprint of that key and a salt whose size depends on the hash algorithm
            bool isV6 = sigPack.Version == OnePassSignaturePacket.Version6;
            m_unusable = isV6 != (pubKey.Version == PublicKeyPacket.Version6)
                // the announced algorithm has to be the one of the key, as for the signature itself
                || !PgpUtilities.IsSignatureAlgorithmCompatible(sigPack.KeyAlgorithm, pubKey.Algorithm);
            if (isV6 && !m_unusable)
            {
                m_unusable = !Arrays.AreEqual(sigPack.GetFingerprint(), pubKey.GetFingerprint())
                    || sigPack.GetSalt().Length != PgpUtilities.GetV6SaltSize(sigPack.HashAlgorithm);
            }
            if (m_unusable)
                return;

            AsymmetricKeyParameter key = pubKey.GetKey();

            // RFC 9580 5.2.3.3: an EdDSALegacy key over Ed448 needs a larger digest than its algorithm alone says
            if (!PgpUtilities.IsHashStrongEnough(sigPack.KeyAlgorithm, sigPack.HashAlgorithm, key))
            {
                m_unusable = true;
                return;
            }

            try
            {
                sig = PgpUtilities.CreateSigner(sigPack.KeyAlgorithm, sigPack.HashAlgorithm, key);
            }
            catch (Exception e)
            {
                throw new PgpException("can't set up signature object.", e);
            }

            try
            {
                sig.Init(false, key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

            if (isV6)
            {
                // RFC 9580 5.2.4: the salt is hashed before the data
                byte[] salt = sigPack.GetSalt();
                sig.BlockUpdate(salt, 0, salt.Length);

                if (!(sig is PgpDigestSigner))
                {
                    m_prefixDigest = PgpUtilities.CreateDigest(sigPack.HashAlgorithm);
                    m_prefixDigest.BlockUpdate(salt, 0, salt.Length);
                }
            }
        }

        private void DoUpdateSigner(byte b)
        {
            sig.Update(b);
            m_prefixDigest?.Update(b);
        }

        private void DoUpdateSigner(byte[] bytes, int off, int length)
        {
            sig.BlockUpdate(bytes, off, length);
            m_prefixDigest?.BlockUpdate(bytes, off, length);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void DoUpdateSigner(ReadOnlySpan<byte> input)
        {
            sig.BlockUpdate(input);
            m_prefixDigest?.BlockUpdate(input);
        }
#endif

        public void Update(byte b)
        {
            if (m_unusable)
                return;

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                DoCanonicalUpdateByte(b);
            }
            else
            {
                DoUpdateSigner(b);
            }
        }

        private void DoCanonicalUpdateByte(byte b)
        {
            if (b == '\r')
            {
                DoUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    DoUpdateCRLF();
                }
            }
            else
            {
                DoUpdateSigner(b);
            }

            lastb = b;
        }

        private void DoUpdateCRLF()
        {
            DoUpdateSigner((byte)'\r');
            DoUpdateSigner((byte)'\n');
        }

        public void Update(params byte[] bytes) => Update(bytes, 0, bytes.Length);

        public void Update(byte[] bytes, int off, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(bytes.AsSpan(off, length));
#else
            if (m_unusable)
                return;

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                DoUpdateSigner(bytes, off, length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
            if (m_unusable)
                return;

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                DoUpdateSigner(input);
            }
        }
#endif

        /// <summary>Verify the calculated signature against the passed in PgpSignature.</summary>
        public bool Verify(PgpSignature pgpSig)
        {
            if (m_unusable)
                return false;

            // the signature has to be the one that this packet announces
            if (pgpSig.IsUnusable || pgpSig.SignatureType != SignatureType)
                return false;
            if (pgpSig.HashAlgorithm != HashAlgorithm ||
                !PgpUtilities.IsSignatureAlgorithmCompatible(pgpSig.KeyAlgorithm, KeyAlgorithm))
            {
                return false;
            }

            bool isV6 = sigPack.Version == OnePassSignaturePacket.Version6;
            if (isV6 != (pgpSig.Version == SignaturePacket.Version6))
                return false;

            // RFC 9580 5.2.3.35: an issuer fingerprint names a key of the version of the signature
            if (pgpSig.HasIssuerFingerprintVersionMismatch)
                return false;

            if (isV6)
            {
                if (!Arrays.AreEqual(sigPack.GetSalt(), pgpSig.GetSalt()))
                    return false;

                IssuerFingerprint issuer = pgpSig.GetHashedSubPackets()?.GetIssuerFingerprint()
                    ?? pgpSig.GetUnhashedSubPackets()?.GetIssuerFingerprint();
                if (issuer != null && !Arrays.AreEqual(issuer.GetFingerprint(), sigPack.GetFingerprint()))
                    return false;
            }

            if (!PgpUtilities.IsHashStrongEnough(pgpSig.KeyAlgorithm, pgpSig.HashAlgorithm))
                return false;

            byte[] trailer = pgpSig.GetSignatureTrailer();

            DoUpdateSigner(trailer, 0, trailer.Length);

            if (!sig.VerifySignature(pgpSig.GetSignature()))
                return false;

            return !isV6 || DigestPrefixMatches(pgpSig);
        }

        private bool DigestPrefixMatches(PgpSignature pgpSig)
        {
            byte[] digest = m_prefixDigest != null
                ? DigestUtilities.DoFinal(m_prefixDigest)
                : (sig as PgpDigestSigner)?.LastDigest;

            byte[] prefix = pgpSig.GetDigestPrefix();

            return digest != null && digest.Length >= 2 && prefix.Length == 2
                && digest[0] == prefix[0] && digest[1] == prefix[1];
        }

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => sigPack.KeyId;

        public int SignatureType => sigPack.SignatureType;

        /// <summary>The version of the one-pass signature packet: 3, or 6 (RFC 9580 5.4).</summary>
        public int Version => sigPack.Version;

        /// <summary>The salt of the signature that this packet announces (version 6 only).</summary>
        /// <returns>A copy of the salt, or null for version 3.</returns>
        public byte[] GetSalt() => sigPack.GetSalt();

        /// <summary>The fingerprint of the signing key (version 6 only).</summary>
        /// <returns>A copy of the fingerprint, or null for version 3.</returns>
        public byte[] GetFingerprint() => sigPack.GetFingerprint();

        public HashAlgorithmTag HashAlgorithm => sigPack.HashAlgorithm;

        public PublicKeyAlgorithmTag KeyAlgorithm => sigPack.KeyAlgorithm;

        public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(Stream outStr) => sigPack.Encode(BcpgOutputStream.Wrap(outStr));
    }
}
