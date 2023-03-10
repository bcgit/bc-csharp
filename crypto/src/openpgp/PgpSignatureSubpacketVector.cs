using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Container for a list of signature subpackets.</remarks>
    public class PgpSignatureSubpacketVector
    {
        public static PgpSignatureSubpacketVector FromSubpackets(SignatureSubpacket[] packets)
        {
            return new PgpSignatureSubpacketVector(packets ?? new SignatureSubpacket[0]);
        }

        private readonly SignatureSubpacket[] packets;

		internal PgpSignatureSubpacketVector(SignatureSubpacket[] packets)
        {
            this.packets = packets;
        }

		public SignatureSubpacket GetSubpacket(SignatureSubpacketTag type)
        {
            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].SubpacketType == type)
                    return packets[i];
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
            for (int i = 0; i < packets.Length; ++i)
            {
                if (packets[i].SubpacketType == type)
                {
                    ++count;
                }
            }

            SignatureSubpacket[] result = new SignatureSubpacket[count];

            int pos = 0;
            for (int i = 0; i < packets.Length; ++i)
            {
                if (packets[i].SubpacketType == type)
                {
                    result[pos++] = packets[i];
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
                    l[i] = new PgpSignature(SignaturePacket.FromByteArray(sigs[i].GetData()));
                }
                catch (IOException e)
                {
                    throw new PgpException("Unable to parse signature packet: " + e.Message, e);
                }
            }

            return new PgpSignatureList(l);
        }

        public NotationData[] GetNotationDataOccurrences()
		{
			SignatureSubpacket[] notations = GetSubpackets(SignatureSubpacketTag.NotationData);
			NotationData[] vals = new NotationData[notations.Length];

			for (int i = 0; i < notations.Length; i++)
			{
				vals[i] = (NotationData) notations[i];
			}

			return vals;
		}

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

        public long GetIssuerKeyId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IssuerKeyId);

            return p == null ? 0 : ((IssuerKeyId)p).KeyId;
        }

		public bool HasSignatureCreationTime()
		{
			return GetSubpacket(SignatureSubpacketTag.CreationTime) != null;
		}

		public DateTime GetSignatureCreationTime()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.CreationTime)
                ?? throw new PgpException("SignatureCreationTime not available");

            return ((SignatureCreationTime)p).GetTime();
        }

        public bool HasSignatureExpirationTime()
        {
            return GetSubpacket(SignatureSubpacketTag.ExpireTime) != null;
        }

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

		public int[] GetPreferredHashAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredHashAlgorithms);

			return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

		public int[] GetPreferredSymmetricAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredSymmetricAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

		public int[] GetPreferredCompressionAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredCompressionAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        public int[] GetPreferredAeadAlgorithms()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PreferredAeadAlgorithms);

            return p == null ? null : ((PreferredAlgorithms)p).GetPreferences();
        }

        public int GetKeyFlags()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.KeyFlags);

            return p == null ? 0 : ((KeyFlags)p).Flags;
        }

		public string GetSignerUserId()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.SignerUserId);

			return p == null ? null : ((SignerUserId)p).GetId();
        }

		public bool IsPrimaryUserId()
		{
			PrimaryUserId primaryId = (PrimaryUserId)GetSubpacket(SignatureSubpacketTag.PrimaryUserId);

            return primaryId != null && primaryId.IsPrimaryUserId();
		}

		public SignatureSubpacketTag[] GetCriticalTags()
        {
            int count = 0;
            for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].IsCritical())
                {
                    count++;
                }
            }

			SignatureSubpacketTag[] list = new SignatureSubpacketTag[count];

			count = 0;

			for (int i = 0; i != packets.Length; i++)
            {
                if (packets[i].IsCritical())
                {
                    list[count++] = packets[i].SubpacketType;
                }
            }

			return list;
        }

        public SignatureTarget GetSignatureTarget()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.SignatureTarget);

            return p == null ? null : new SignatureTarget(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public Features GetFeatures()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Features);

            return p == null ? null : new Features(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public IssuerFingerprint GetIssuerFingerprint()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IssuerFingerprint);

            return p == null ? null : new IssuerFingerprint(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public IntendedRecipientFingerprint GetIntendedRecipientFingerprint()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.IntendedRecipientFingerprint);

            return p == null ? null : new IntendedRecipientFingerprint(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public IntendedRecipientFingerprint[] GetIntendedRecipientFingerprints()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.IntendedRecipientFingerprint);
            IntendedRecipientFingerprint[] recipients = new IntendedRecipientFingerprint[subpackets.Length];
            for (int i = 0; i < recipients.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                recipients[i] = new IntendedRecipientFingerprint(p.IsCritical(), p.IsLongLength(), p.GetData());
            }
            return recipients;
        }

        public Exportable GetExportable()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Exportable);

            return p == null ? null : new Exportable(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public bool IsExportable()
        {
            Exportable exportable = GetExportable();
            return exportable == null || exportable.IsExportable();
        }

        public PolicyUrl GetPolicyUrl()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.PolicyUrl);

            return p == null ? null : new PolicyUrl(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public PolicyUrl[] GetPolicyUrls()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.PolicyUrl);
            PolicyUrl[] policyUrls = new PolicyUrl[subpackets.Length];
            for (int i = 0; i < subpackets.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                policyUrls[i] = new PolicyUrl(p.IsCritical(), p.IsLongLength(), p.GetData());
            }
            return policyUrls;
        }

        public RegularExpression GetRegularExpression()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.RegExp);

            return p == null ? null : new RegularExpression(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public RegularExpression[] GetRegularExpressions()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.RegExp);
            RegularExpression[] regexes = new RegularExpression[subpackets.Length];
            for (int i = 0; i < regexes.Length; i++)
            {
                SignatureSubpacket p = subpackets[i];
                regexes[i] = new RegularExpression(p.IsCritical(), p.IsLongLength(), p.GetData());
            }
            return regexes;
        }

        public Revocable GetRevocable()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.Revocable);

            return p == null ? null : new Revocable(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public bool IsRevocable()
        {
            Revocable revocable = GetRevocable();
            return revocable == null || revocable.IsRevocable();
        }

        public RevocationKey[] GetRevocationKeys()
        {
            SignatureSubpacket[] subpackets = GetSubpackets(SignatureSubpacketTag.RevocationKey);
            RevocationKey[] revocationKeys = new RevocationKey[subpackets.Length];
            for (int i = 0; i < revocationKeys.Length; i++)
            {
                SignatureSubpacket p = subpackets[i]; 
                revocationKeys[i] = new RevocationKey(p.IsCritical(), p.IsLongLength(), p.GetData());
            }
            return revocationKeys;
        }

        public RevocationReason GetRevocationReason()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.RevocationReason);

            return p == null ? null : new RevocationReason(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

        public TrustSignature GetTrust()
        {
            SignatureSubpacket p = GetSubpacket(SignatureSubpacketTag.TrustSig);

            return p == null ? null : new TrustSignature(p.IsCritical(), p.IsLongLength(), p.GetData());
        }

		/// <summary>Return the number of packets this vector contains.</summary>
		public int Count => packets.Length;

		internal SignatureSubpacket[] ToSubpacketArray()
        {
            return packets;
        }

        /**
         * Return a copy of the subpackets in this vector.
         *
         * @return an array containing the vector subpackets in order.
         */
        public SignatureSubpacket[] ToArray()
        {
            return (SignatureSubpacket[])packets.Clone();
        }
    }
}
