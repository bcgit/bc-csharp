using System;
using System.IO;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {

        /**
         * Unprotected.
         */
        public const int UsageNone = 0x00;

        /**
         * Malleable CFB.
         * Malleable-CFB-encrypted keys are vulnerable to corruption attacks
         * that can cause leakage of secret data when the secret key is used.
         *
         * @see <a href="https://eprint.iacr.org/2002/076">
         * Klíma, V. and T. Rosa,
         * "Attack on Private Signature Keys of the OpenPGP Format,
         * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
         * @see <a href="https://www.kopenpgp.com/">
         * Bruseghini, L., Paterson, K. G., and D. Huigens,
         * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
         * @deprecated Use of MalleableCFB is deprecated.
         * For v4 keys, use {@link #USAGE_SHA1} instead.
         * For v6 keys use {@link #USAGE_AEAD} instead.
         */
        public const int UsageChecksum = 0xff;

        /**
         * CFB.
         * CFB-encrypted keys are vulnerable to corruption attacks that can
         * cause leakage of secret data when the secret key is use.
         *
         * @see <a href="https://eprint.iacr.org/2002/076">
         * Klíma, V. and T. Rosa,
         * "Attack on Private Signature Keys of the OpenPGP Format,
         * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
         * @see <a href="https://www.kopenpgp.com/">
         * Bruseghini, L., Paterson, K. G., and D. Huigens,
         * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
         */
        public const int UsageSha1 = 0xfe;

        /**
         * AEAD.
         * This usage protects against above-mentioned attacks.
         * Passphrase-protected secret key material in a v6 Secret Key or
         * v6 Secret Subkey packet SHOULD be protected with AEAD encryption
         * unless it will be transferred to an implementation that is known
         * to not support AEAD.
         * Users should migrate to AEAD with all due speed.
         */
        public const int UsageAead = 0xfd;


        private readonly PublicKeyPacket pubKeyPacket;
        private readonly byte[] secKeyData;
		private readonly int s2kUsage;
		private readonly SymmetricKeyAlgorithmTag encAlgorithm;
        private readonly S2k s2k;
        private readonly byte[] iv;
        private readonly AeadAlgorithmTag aeadAlgorithm;

        private bool HasS2KSpecifier
            => (s2kUsage == UsageChecksum || s2kUsage == UsageSha1 || s2kUsage == UsageAead);

        internal SecretKeyPacket(
            BcpgInputStream bcpgIn)
        {
			if (this is SecretSubkeyPacket)
			{
				pubKeyPacket = new PublicSubkeyPacket(bcpgIn);
			}
			else
			{
				pubKeyPacket = new PublicKeyPacket(bcpgIn);
			}

            int version = pubKeyPacket.Version;
            s2kUsage = bcpgIn.ReadByte();

            if (version == PublicKeyPacket.Version6 && s2kUsage != UsageNone)
            {
                // TODO: Use length to parse unknown parameters
                int conditionalParameterLength = bcpgIn.ReadByte();
            }

            if (HasS2KSpecifier)
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();
            }
            else
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag)s2kUsage;
            }

            if (s2kUsage == UsageAead)
            {
                aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.ReadByte();
            }

            if (HasS2KSpecifier)
            {
                if (version == PublicKeyPacket.Version6)
                {
                    // TODO: Use length to parse unknown S2Ks
                    int s2kLen = bcpgIn.ReadByte();
                }
                s2k = new S2k(bcpgIn);
            }
            if (s2kUsage == UsageAead)
            {
                iv = new byte[AeadUtils.GetIVLength(aeadAlgorithm)];
                bcpgIn.ReadFully(iv);
            }

            bool isGNUDummyNoPrivateKey = s2k != null
                    && s2k.Type == S2k.GnuDummyS2K
                    && s2k.ProtectionMode == S2k.GnuProtectionModeNoPrivateKey;

            if (!(isGNUDummyNoPrivateKey))
            {
                if (s2kUsage != 0 && iv == null)
                {
                    if ((int)encAlgorithm < 7)
                    {
                        iv = new byte[8];
                    }
                    else
                    {
                        iv = new byte[16];
                    }
                    bcpgIn.ReadFully(iv);
                }
            }

            secKeyData = bcpgIn.ReadAll();
        }

		public SecretKeyPacket(
            PublicKeyPacket				pubKeyPacket,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            S2k							s2k,
            byte[]						iv,
            byte[]						secKeyData)
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;

			if (encAlgorithm != SymmetricKeyAlgorithmTag.Null)
			{
				this.s2kUsage = UsageChecksum;
			}
			else
			{
				this.s2kUsage = UsageNone;
			}

			this.s2k = s2k;
			this.iv = Arrays.Clone(iv);
			this.secKeyData = secKeyData;
        }

		public SecretKeyPacket(
			PublicKeyPacket				pubKeyPacket,
			SymmetricKeyAlgorithmTag	encAlgorithm,
			int							s2kUsage,
			S2k							s2k,
			byte[]						iv,
			byte[]						secKeyData)
		{
			this.pubKeyPacket = pubKeyPacket;
			this.encAlgorithm = encAlgorithm;
			this.s2kUsage = s2kUsage;
			this.s2k = s2k;
			this.iv = Arrays.Clone(iv);
			this.secKeyData = secKeyData;
		}


        public SecretKeyPacket(
            PublicKeyPacket pubKeyPacket,
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            int s2kUsage,
            S2k s2k,
            byte[] iv,
            byte[] secKeyData)
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;
            this.aeadAlgorithm = aeadAlgorithm;
            this.s2kUsage = s2kUsage;
            this.s2k = s2k;
            this.iv = Arrays.Clone(iv);
            this.secKeyData = secKeyData;

            if (s2k != null && s2k.Type == S2k.Argon2 && s2kUsage != UsageAead)
            {
                throw new ArgumentException("Argon2 is only used with AEAD (S2K usage octet 253)");
            }

            if (pubKeyPacket.Version == PublicKeyPacket.Version6)
            {
                if (s2kUsage == UsageChecksum)
                {
                    throw new ArgumentException("Version 6 keys MUST NOT use S2K usage UsageChecksum");
                }
            }
        }

        public SymmetricKeyAlgorithmTag EncAlgorithm
        {
			get { return encAlgorithm; }
        }

        public AeadAlgorithmTag GetAeadAlgorithm()
        {
            return aeadAlgorithm;
        }

        public int S2kUsage
		{
			get { return s2kUsage; }
		}

		public byte[] GetIV()
        {
            return Arrays.Clone(iv);
        }

		public S2k S2k
        {
			get { return s2k; }
        }

		public PublicKeyPacket PublicKeyPacket
        {
			get { return pubKeyPacket; }
        }

		public byte[] GetSecretKeyData()
        {
            return secKeyData;
        }



        private byte[] EncodeConditionalParameters()
        {
            using (MemoryStream conditionalParameters = new MemoryStream())
            {
                if (HasS2KSpecifier)
                {
                    conditionalParameters.WriteByte((byte)encAlgorithm);
                    if (s2kUsage == UsageAead)
                    {
                        conditionalParameters.WriteByte((byte)aeadAlgorithm);
                    }
                    byte[] encodedS2K = s2k.GetEncoded();
                    if (pubKeyPacket.Version == PublicKeyPacket.Version6)
                    {
                        conditionalParameters.WriteByte((byte)encodedS2K.Length);
                    }
                    conditionalParameters.Write(encodedS2K, 0, encodedS2K.Length);
                }
                if (iv != null)
                {
                    // since USAGE_AEAD and other types that use an IV are mutually exclusive,
                    // we use the IV field for both v4 IVs and v6 AEAD nonces
                    conditionalParameters.Write(iv, 0, iv.Length);
                }

                return conditionalParameters.ToArray();
            }
        }

		public byte[] GetEncodedContents()
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {
                    pOut.Write(pubKeyPacket.GetEncodedContents());
                    pOut.WriteByte((byte)s2kUsage);

                    // conditional parameters
                    byte[] conditionalParameters = EncodeConditionalParameters();
                    if (pubKeyPacket.Version == PublicKeyPacket.Version6 && s2kUsage != UsageNone)
                    {
                        pOut.WriteByte((byte)conditionalParameters.Length);
                    }
                    pOut.Write(conditionalParameters);

                    // encrypted secret key
                    if (secKeyData != null && secKeyData.Length > 0)
                    {
                        pOut.Write(secKeyData);
                    }
                    pOut.Close();
                }
                return bOut.ToArray();
            }
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretKey, GetEncodedContents());
        }
    }
}
