using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Container for a list of signature subpackets.</remarks>
    public class PgpSignatureSubpacketVector
    {
        /// <summary>Create a vector from an array of subpackets.</summary>
        /// <param name="packets">The subpackets.</param>
        /// <returns>The vector.</returns>
        public static PgpSignatureSubpacketVector FromSubpackets(SignatureSubpacket[] packets) =>
            new PgpSignatureSubpacketVector(packets ?? Array.Empty<SignatureSubpacket>());

        private readonly SignatureSubpacket[] m_packets;

        internal PgpSignatureSubpacketVector(SignatureSubpacket[] packets)
        {
            m_packets = packets;
        }

        /// <summary>Get the first subpacket of the given type.</summary>
        /// <param name="type">The subpacket type.</param>
        /// <returns>The subpacket, or null if there is none.</returns>
        public SignatureSubpacket GetSubpacket(SignatureSubpacketTag type)
        {
            for (int i = 0; i != m_packets.Length; i++)
            {
                if (m_packets[i].SubpacketType == type)
                    return m_packets[i];
            }

            return null;
        }

        /**
         * Return true if a particular subpacket type exists.
         *
         * @param type type to look for.
         * @return true if present, false otherwise.
         */
        public bool HasSubpacket(SignatureSubpacketTag type)
        {
            return GetSubpacket(type) != null;
        }

        /**
         * Return all signature subpackets of the passed in type.
         * @param type subpacket type code
         * @return an array of zero or more matching subpackets.
         */
        public SignatureSubpacket[] GetSubpackets(SignatureSubpacketTag type)
        {
            int count = 0;
            for (int i = 0; i < m_packets.Length; ++i)
            {
                if (m_packets[i].SubpacketType == type)
                {
                    ++count;
                }
            }

            SignatureSubpacket[] result = new SignatureSubpacket[count];

            int pos = 0;
            for (int i = 0; i < m_packets.Length; ++i)
            {
                if (m_packets[i].SubpacketType == type)
                {
                    result[pos++] = m_packets[i];
                }
            }

            return result;
        }

        /// <exception cref="PgpException"/>
        public PgpSignatureList GetEmbeddedSignatures()
        {
            SignatureSubpacket[] sigs = GetSubpackets(SignatureSubpacketTag.EmbeddedSignature);
            PgpSignature[] l = new PgpSignature[sigs.Length];

            for (int i = 0; i < sigs.Length; i++)
            {
                try
                {
                    l[i] = new PgpSignature(SignaturePacket.FromByteArray(sigs[i].Data));
                }
                catch (IOException e)
                {
                    throw new PgpException("Unable to parse signature packet: " + e.Message, e);
                }
            }

            return new PgpSignatureList(l);
        }

        /// <summary>Return the notation data occurrences.</summary>
        public NotationData[] GetNotationDataOccurrences()
        {
            SignatureSubpacket[] notations = GetSubpackets(SignatureSubpacketTag.NotationData);
            NotationData[] vals = new NotationData[notations.Length];

            for (int i = 0; i < notations.Length; i++)
            {
                vals[i] = (NotationData)notations[i];
            }

            return vals;
        }

        /// <summary>Get the notation data subpackets with the given name.</summary>
        /// <param name="notationName">The notation name.</param>
        /// <returns>The matching notation data.</returns>
        public NotationData[] GetNotationDataOccurrences(string notationName)
        {
            NotationData[] notations = GetNotationDataOccurrences();
            var notationsWithName = new List<NotationData>();
            for (int i = 0; i != notations.Length; i++)
            {
                NotationData notation = notations[i];
                if (notation.GetNotationName().Equals(notationName))
                {
                    notationsWithName.Add(notation);
                }
            }
            return notationsWithName.ToArray();
        }

        /// <summary>Return the issuer key id.</summary>
        public long GetIssuerKeyId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IssuerKeyId);

            return p == null ? 0 : ((IssuerKeyId)p).GetKeyID();
        }

        /// <summary>Determine whether there is a signature creation time subpacket.</summary>
        /// <returns>true if there is one, false otherwise.</returns>
        public bool HasSignatureCreationTime() => GetSubpacket(SignatureSubpacketTag.CreationTime) != null;

        /// <summary>Return the signature creation time.</summary>
        public DateTime GetSignatureCreationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.CreationTime)
                ?? throw new PgpException("SignatureCreationTime not available");

            return ((SignatureCreationTime)p).GetTime();
        }

        /// <summary>Determine whether there is a signature expiration time subpacket.</summary>
        /// <returns>true if there is one, false otherwise.</returns>
        public bool HasSignatureExpirationTime() => GetSubpacket(SignatureSubpacketTag.ExpireTime) != null;

        /// <summary>
        /// Return the number of seconds a signature is valid for after its creation date.
        /// A value of zero means the signature never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public long GetSignatureExpirationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.ExpireTime);

            return p == null ? 0 : ((SignatureExpirationTime)p).Time;
        }

        /// <summary>Determine whether there is a key expiration time subpacket.</summary>
        /// <returns>true if there is one, false otherwise.</returns>
        public bool HasKeyExpirationTime() => GetSubpacket(SignatureSubpacketTag.KeyExpireTime) != null;

        /// <summary>
        /// Return the number of seconds a key is valid for after its creation date.
        /// A value of zero means the key never expires.
        /// </summary>
        /// <returns>Seconds a signature is valid for.</returns>
        public long GetKeyExpirationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.KeyExpireTime);

            return p == null ? 0 : ((KeyExpirationTime)p).Time;
        }

        /// <summary>Return the preferred hash algorithms.</summary>
        public int[] GetPreferredHashAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredHashAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        /// <summary>Return the preferred symmetric algorithms.</summary>
        public int[] GetPreferredSymmetricAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredSymmetricAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        /// <summary>Return the preferred compression algorithms.</summary>
        public int[] GetPreferredCompressionAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredCompressionAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        /// <summary>Return the preferred aead algorithms.</summary>
        public int[] GetPreferredAeadAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredAeadAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        /// <summary>Return the key flags.</summary>
        public int GetKeyFlags()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.KeyFlags);

            return p == null ? 0 : ((KeyFlags)p).Flags;
        }

        /// <summary>Return the signer user id.</summary>
        public string GetSignerUserId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.SignerUserId);

            return p == null ? null : ((SignerUserId)p).GetId();
        }

        /// <summary>Determine whether the vector marks the user ID as the primary user ID.</summary>
        /// <returns>true if it does, false otherwise.</returns>
        public bool IsPrimaryUserId()
        {
            PrimaryUserId primaryId = (PrimaryUserId)GetSubpacket(SignatureSubpacketTag.PrimaryUserId);

            return primaryId != null && primaryId.IsPrimaryUserId();
        }

        /// <summary>Return the critical tags.</summary>
        public SignatureSubpacketTag[] GetCriticalTags()
        {
            int count = 0;
            for (int i = 0; i != m_packets.Length; i++)
            {
                if (m_packets[i].IsCritical())
                {
                    count++;
                }
            }

            SignatureSubpacketTag[] list = new SignatureSubpacketTag[count];

            count = 0;

            for (int i = 0; i != m_packets.Length; i++)
            {
                if (m_packets[i].IsCritical())
                {
                    list[count++] = m_packets[i].SubpacketType;
                }
            }

            return list;
        }

        /// <summary>Return the signature target.</summary>
        public SignatureTarget GetSignatureTarget()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.SignatureTarget);

            return p == null ? null : new SignatureTarget(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the features.</summary>
        public Features GetFeatures()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Features);

            return p == null ? null : new Features(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the issuer fingerprint.</summary>
        public IssuerFingerprint GetIssuerFingerprint()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IssuerFingerprint);

            return p == null ? null : new IssuerFingerprint(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the intended recipient fingerprint.</summary>
        public IntendedRecipientFingerprint GetIntendedRecipientFingerprint()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IntendedRecipientFingerprint);

            return p == null ? null : new IntendedRecipientFingerprint(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the intended recipient fingerprints.</summary>
        public IntendedRecipientFingerprint[] GetIntendedRecipientFingerprints()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.IntendedRecipientFingerprint);
            IntendedRecipientFingerprint[] recipients = new IntendedRecipientFingerprint[subpackets.Length];
            for (int i = 0; i < recipients.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                recipients[i] = new IntendedRecipientFingerprint(p.IsCritical(), p.IsLongLength(), p.Data);
            }
            return recipients;
        }

        /// <summary>Return the exportable.</summary>
        public Exportable GetExportable()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Exportable);

            return p == null ? null : new Exportable(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Determine whether the vector marks the signature as exportable.</summary>
        /// <returns>true if it is exportable (the default), false otherwise.</returns>
        public bool IsExportable()
        {
            Exportable exportable = GetExportable();
            return exportable == null || exportable.IsExportable();
        }

        /// <summary>Return the policy url.</summary>
        public PolicyUrl GetPolicyUrl()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PolicyUrl);

            return p == null ? null : new PolicyUrl(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the policy urls.</summary>
        public PolicyUrl[] GetPolicyUrls()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.PolicyUrl);
            PolicyUrl[] policyUrls = new PolicyUrl[subpackets.Length];
            for (int i = 0; i < subpackets.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                policyUrls[i] = new PolicyUrl(p.IsCritical(), p.IsLongLength(), p.Data);
            }
            return policyUrls;
        }

        /// <summary>Return the regular expression.</summary>
        public RegularExpression GetRegularExpression()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.RegExp);

            return p == null ? null : new RegularExpression(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the regular expressions.</summary>
        public RegularExpression[] GetRegularExpressions()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.RegExp);
            RegularExpression[] regexes = new RegularExpression[subpackets.Length];
            for (int i = 0; i < regexes.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                regexes[i] = new RegularExpression(p.IsCritical(), p.IsLongLength(), p.Data);
            }
            return regexes;
        }

        /// <summary>Return the revocable.</summary>
        public Revocable GetRevocable()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Revocable);

            return p == null ? null : new Revocable(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Determine whether the vector marks the signature as revocable.</summary>
        /// <returns>true if it is revocable (the default), false otherwise.</returns>
        public bool IsRevocable()
        {
            Revocable revocable = GetRevocable();
            return revocable == null || revocable.IsRevocable();
        }

        /// <summary>Return the revocation keys.</summary>
        public RevocationKey[] GetRevocationKeys()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.RevocationKey);
            RevocationKey[] revocationKeys = new RevocationKey[subpackets.Length];
            for (int i = 0; i < revocationKeys.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                revocationKeys[i] = new RevocationKey(p.IsCritical(), p.IsLongLength(), p.Data);
            }
            return revocationKeys;
        }

        /// <summary>Return the revocation reason.</summary>
        public RevocationReason GetRevocationReason()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.RevocationReason);

            return p == null ? null : new RevocationReason(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the trust.</summary>
        public TrustSignature GetTrust()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.TrustSig);

            return p == null ? null : new TrustSignature(p.IsCritical(), p.IsLongLength(), p.Data);
        }

        /// <summary>Return the number of packets this vector contains.</summary>
        public int Count => m_packets.Length;

        internal SignatureSubpacket[] ToSubpacketArray() => m_packets;

        /**
         * Return a copy of the subpackets in this vector.
         *
         * @return an array containing the vector subpackets in order.
         */
        public SignatureSubpacket[] ToArray() => (SignatureSubpacket[])m_packets.Clone();
    }
}
