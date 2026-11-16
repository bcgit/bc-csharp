using System;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for signature subpackets.</remarks>
    public class PgpSignatureSubpacketGenerator
    {
        private readonly List<SignatureSubpacket> list = new List<SignatureSubpacket>();

        /// <summary>
        ///Base constructor, creates an empty generator.
        /// </summary>
        public PgpSignatureSubpacketGenerator()
        {
        }

        ///  <summary>
        ///  Constructor for pre-initialising the generator from an existing one.
        ///  </summary>
        ///  <param name="sigSubV">
        ///  sigSubV an initial set of subpackets.
        ///  </param>
        public PgpSignatureSubpacketGenerator(PgpSignatureSubpacketVector sigSubV)
        {
            if (sigSubV != null)
            {
                SignatureSubpacket[] subs = sigSubV.ToSubpacketArray();
                for (int i = 0; i != sigSubV.Count; i++)
                {
                    list.Add(subs[i]);
                }
            }
        }

        /// <summary>Set the revocable subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="isRevocable">true if the signature is revocable.</param>
        public void SetRevocable(bool isCritical, bool isRevocable)
        {
            list.Add(new Revocable(isCritical, isRevocable));
        }

        /// <summary>Set the exportable certification subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="isExportable">true if the certification is exportable.</param>
        public void SetExportable(bool isCritical, bool isExportable)
        {
            list.Add(new Exportable(isCritical, isExportable));
        }

        /// <summary>Set the features subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="feature">The feature flags.</param>
        public void SetFeature(bool isCritical, byte feature)
        {
            list.Add(new Features(isCritical, feature));
        }

        /// <summary>
        /// Add a TrustSignature packet to the signature. The values for depth and trust are largely
        /// installation dependent but there are some guidelines in RFC 4880 - 5.2.3.13.
        /// </summary>
        /// <param name="isCritical">true if the packet is critical.</param>
        /// <param name="depth">depth level.</param>
        /// <param name="trustAmount">trust amount.</param>
        public void SetTrust(bool isCritical, int depth, int trustAmount)
        {
            list.Add(new TrustSignature(isCritical, depth, trustAmount));
        }

        /// <summary>
        /// Set the number of seconds a key is valid for after the time of its creation.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <param name="isCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="seconds">The number of seconds the key is valid, or zero if no expiry.</param>
        public void SetKeyExpirationTime(bool isCritical, long seconds)
        {
            list.Add(new KeyExpirationTime(isCritical, seconds));
        }

        /// <summary>
        /// Set the number of seconds a signature is valid for after the time of its creation.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <param name="isCritical">True, if should be treated as critical, false otherwise.</param>
        /// <param name="seconds">The number of seconds the signature is valid, or zero if no expiry.</param>
        public void SetSignatureExpirationTime(bool isCritical, long seconds)
        {
            list.Add(new SignatureExpirationTime(isCritical, seconds));
        }

        /// <summary>
        /// Set the creation time for the signature.
        /// <p>
        /// Note: this overrides the generation of a creation time when the signature
        /// is generated.</p>
        /// </summary>
        public void SetSignatureCreationTime(bool isCritical, DateTime date)
        {
            list.Add(new SignatureCreationTime(isCritical, date));
        }

        /// <summary>Set the preferred hash algorithms, replacing any existing subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="algorithms">The algorithms, in order of preference.</param>
        public void SetPreferredHashAlgorithms(bool isCritical, int[] algorithms)
        {
            list.Add(new PreferredAlgorithms(SignatureSubpacketTag.PreferredHashAlgorithms, isCritical, algorithms));
        }

        /// <summary>Set the preferred symmetric algorithms, replacing any existing subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="algorithms">The algorithms, in order of preference.</param>
        public void SetPreferredSymmetricAlgorithms(bool isCritical, int[] algorithms)
        {
            list.Add(new PreferredAlgorithms(SignatureSubpacketTag.PreferredSymmetricAlgorithms, isCritical, algorithms));
        }

        /// <summary>Set the preferred compression algorithms, replacing any existing subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="algorithms">The algorithms, in order of preference.</param>
        public void SetPreferredCompressionAlgorithms(bool isCritical, int[] algorithms)
        {
            list.Add(new PreferredAlgorithms(SignatureSubpacketTag.PreferredCompressionAlgorithms, isCritical, algorithms));
        }

        /// <summary>Set the preferred AEAD algorithm combinations, replacing any existing subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="algorithms">The algorithms, in order of preference.</param>
        public void SetPreferredAeadAlgorithms(bool isCritical, int[] algorithms)
        {
            list.Add(new PreferredAlgorithms(SignatureSubpacketTag.PreferredAeadAlgorithms, isCritical, algorithms));
        }

        /// <summary>Add a policy URL subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="policyUrl">The policy URL.</param>
        public void AddPolicyUrl(bool isCritical, string policyUrl)
        {
            list.Add(new PolicyUrl(isCritical, policyUrl));
        }

        /// <summary>Set the key flags subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="flags">The key flags.</param>
        public void SetKeyFlags(bool isCritical, int flags)
        {
            list.Add(new KeyFlags(isCritical, flags));
        }

        /// <summary>Set the signer user ID subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="userId">The user ID.</param>
        [Obsolete("Use 'AddSignerUserId' instead")]
        public void SetSignerUserId(bool isCritical, string userId)
        {
            AddSignerUserId(isCritical, userId);
        }

        /// <summary>Add a signer user ID subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="userId">The user ID.</param>
        public void AddSignerUserId(bool isCritical, string userId)
        {
            if (userId == null)
                throw new ArgumentNullException("userId");

            list.Add(new SignerUserId(isCritical, userId));
        }

        /// <summary>Set the signer user ID subpacket from raw bytes, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="rawUserId">The user ID as raw bytes.</param>
        public void SetSignerUserId(bool isCritical, byte[] rawUserId)
        {
            if (rawUserId == null)
                throw new ArgumentNullException("rawUserId");

            list.Add(new SignerUserId(isCritical, false, rawUserId));
        }

        /// <summary>Set the embedded signature subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="pgpSignature">The signature to embed.</param>
        [Obsolete("Use 'AddEmbeddedSignature' instead")]
        public void SetEmbeddedSignature(bool isCritical, PgpSignature pgpSignature)
        {
            AddEmbeddedSignature(isCritical, pgpSignature);
        }

        /// <summary>Add an embedded signature subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="pgpSignature">The signature to embed.</param>
        public void AddEmbeddedSignature(bool isCritical, PgpSignature pgpSignature)
        {
            byte[] sig = pgpSignature.GetEncoded();
            byte[] data;

            // TODO Should be >= ?
            if (sig.Length - 1 > 256)
            {
                data = new byte[sig.Length - 3];
            }
            else
            {
                data = new byte[sig.Length - 2];
            }

            Array.Copy(sig, sig.Length - data.Length, data, 0, data.Length);

            list.Add(new EmbeddedSignature(isCritical, false, data));
        }

        /// <summary>Set the primary user ID subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="isPrimaryUserId">true if the user ID is the primary one.</param>
        public void SetPrimaryUserId(bool isCritical, bool isPrimaryUserId)
        {
            list.Add(new PrimaryUserId(isCritical, isPrimaryUserId));
        }

        /// <summary>Set a notation data subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="isHumanReadable">true if the value is human readable.</param>
        /// <param name="notationName">The notation name.</param>
        /// <param name="notationValue">The notation value.</param>
        [Obsolete("Use 'AddNotationData' instead")]
        public void SetNotationData(bool isCritical, bool isHumanReadable, string notationName, string notationValue)
        {
            AddNotationData(isCritical, isHumanReadable, notationName, notationValue);
        }

        /// <summary>Add a notation data subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="isHumanReadable">true if the value is human readable.</param>
        /// <param name="notationName">The notation name.</param>
        /// <param name="notationValue">The notation value.</param>
        public void AddNotationData(bool isCritical, bool isHumanReadable, string notationName, string notationValue)
        {
            list.Add(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
        }

        /// <summary>
        /// Sets revocation reason subpacket
        /// </summary>
        public void SetRevocationReason(bool isCritical, RevocationReasonTag reason, string description)
        {
            list.Add(new RevocationReason(isCritical, reason, description));
        }

        /// <summary>Set the revocation key subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="keyAlgorithm">The public key algorithm of the revocation key.</param>
        /// <param name="fingerprint">The fingerprint of the revocation key.</param>
        [Obsolete("Use 'AddRevocationKey' instead")]
        public void SetRevocationKey(bool isCritical, PublicKeyAlgorithmTag keyAlgorithm, byte[] fingerprint)
        {
            AddRevocationKey(isCritical, keyAlgorithm, fingerprint);
        }

        /// <summary>Add a revocation key subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="keyAlgorithm">The public key algorithm of the revocation key.</param>
        /// <param name="fingerprint">The fingerprint of the revocation key.</param>
        public void AddRevocationKey(bool isCritical, PublicKeyAlgorithmTag keyAlgorithm, byte[] fingerprint)
        {
            list.Add(new RevocationKey(isCritical, RevocationKeyTag.ClassDefault, keyAlgorithm, fingerprint));
        }

        /// <summary>Sets issuer key subpacket.</summary>
        public void SetIssuerKeyID(bool isCritical, long keyID)
        {
            list.Add(new IssuerKeyId(isCritical, keyID));
        }

        /// <summary>Set the signature target subpacket, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="publicKeyAlgorithm">The public key algorithm of the target signature.</param>
        /// <param name="hashAlgorithm">The hash algorithm of the target signature.</param>
        /// <param name="hashData">The hash of the target signature.</param>
        public void SetSignatureTarget(bool isCritical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
        {
            list.Add(new SignatureTarget(isCritical, publicKeyAlgorithm, hashAlgorithm, hashData));
        }

        /// <summary>Set the issuer fingerprint subpacket from a secret key, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="secretKey">The key of the issuer.</param>
        public void SetIssuerFingerprint(bool isCritical, PgpSecretKey secretKey)
        {
            SetIssuerFingerprint(isCritical, secretKey.PublicKey);
        }

        /// <summary>Set the issuer fingerprint subpacket from a public key, replacing any existing one.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="publicKey">The key of the issuer.</param>
        public void SetIssuerFingerprint(bool isCritical, PgpPublicKey publicKey)
        {
            list.Add(new IssuerFingerprint(isCritical, publicKey.Version, publicKey.GetFingerprint()));
        }

        /// <summary>Add an intended recipient fingerprint subpacket.</summary>
        /// <param name="isCritical">true if the subpacket is critical.</param>
        /// <param name="publicKey">The key of the intended recipient.</param>
        public void AddIntendedRecipientFingerprint(bool isCritical, PgpPublicKey publicKey)
        {
            list.Add(new IntendedRecipientFingerprint(isCritical, publicKey.Version, publicKey.GetFingerprint()));
        }

        /// <summary>Add a ready-made subpacket.</summary>
        /// <param name="subpacket">The subpacket.</param>
        public void AddCustomSubpacket(SignatureSubpacket subpacket)
        {
            list.Add(subpacket);
        }

        /// <summary>Remove a subpacket.</summary>
        /// <param name="packet">The subpacket to remove.</param>
        /// <returns>true if the subpacket was present, false otherwise.</returns>
        public bool RemovePacket(SignatureSubpacket packet)
        {
            return list.Remove(packet);
        }

        /// <summary>Determine whether there is a subpacket of the given type.</summary>
        /// <param name="type">The subpacket type.</param>
        /// <returns>true if there is such a subpacket, false otherwise.</returns>
        public bool HasSubpacket(SignatureSubpacketTag type)
        {
            return null != list.Find(subpacket => subpacket.SubpacketType == type);
        }

        /// <summary>Get the subpackets of the given type.</summary>
        /// <param name="type">The subpacket type.</param>
        /// <returns>The subpackets.</returns>
        public SignatureSubpacket[] GetSubpackets(SignatureSubpacketTag type)
        {
            return list.FindAll(subpacket => subpacket.SubpacketType == type).ToArray();
        }

        /// <summary>Generate the vector of subpackets.</summary>
        /// <returns>The vector.</returns>
        public PgpSignatureSubpacketVector Generate()
        {
            return new PgpSignatureSubpacketVector(list.ToArray());
        }
    }
}
