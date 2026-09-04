using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
	/// <summary>
	/// Internal generator for CMS password-based <c>RecipientInfo</c> values. Configured and used by
	/// <see cref="CmsEnvelopedGenerator.AddPasswordRecipient(CmsPbeKey, string)"/>.
	/// </summary>
	internal class PasswordRecipientInfoGenerator
		: RecipientInfoGenerator
	{
		private AlgorithmIdentifier	keyDerivationAlgorithm;
		private KeyParameter		keyEncryptionKey;
		// TODO Can get this from keyEncryptionKey?		
		private string				keyEncryptionKeyOID;

		/// <summary>Creates an unconfigured password recipient generator.</summary>
		internal PasswordRecipientInfoGenerator()
		{
		}

		/// <summary>Sets the key-derivation algorithm for the password recipient.</summary>
		internal AlgorithmIdentifier KeyDerivationAlgorithm
		{
			set { this.keyDerivationAlgorithm = value; }
		}

		/// <summary>Sets the key-encryption key derived from the password.</summary>
		internal KeyParameter KeyEncryptionKey
		{
			set { this.keyEncryptionKey = value; }
		}

		/// <summary>Sets the symmetric algorithm OID used for RFC 3211 key wrapping.</summary>
		internal string KeyEncryptionKeyOID
		{
			set { this.keyEncryptionKeyOID = value; }
		}

		/// <summary>Wraps <paramref name="contentEncryptionKey"/> using the configured password-derived KEK.</summary>
		/// <param name="contentEncryptionKey">The content-encryption key to wrap.</param>
		/// <param name="random">A source of randomness used for the RFC 3211 IV.</param>
		/// <returns>A CMS RecipientInfo for password-based key management.</returns>
		public RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random)
		{
			byte[] keyBytes = contentEncryptionKey.GetKey();

			string rfc3211WrapperName = CmsEnvelopedHelper.GetRfc3211WrapperName(keyEncryptionKeyOID);
			IWrapper keyWrapper = WrapperUtilities.GetWrapper(rfc3211WrapperName);

			// Note: In Java build, the IV is automatically generated in JCE layer
			int ivLength = Platform.StartsWithIgnoreCase(rfc3211WrapperName, "DES") ? 8 : 16;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var parametersWithIV = ParametersWithIV.Create(keyEncryptionKey, ivLength, random,
                (bytes, random) => random.NextBytes(bytes));
#else
            byte[] iv = new byte[ivLength];
			random.NextBytes(iv);

			var parametersWithIV = new ParametersWithIV(keyEncryptionKey, iv);
#endif

            keyWrapper.Init(true, new ParametersWithRandom(parametersWithIV, random));
        	Asn1OctetString encryptedKey = new DerOctetString(
				keyWrapper.Wrap(keyBytes, 0, keyBytes.Length));

			DerSequence seq = new DerSequence(
				new DerObjectIdentifier(keyEncryptionKeyOID),
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                new DerOctetString(parametersWithIV.InternalIV)
#else
                new DerOctetString(iv)
#endif
            );

			AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
				PkcsObjectIdentifiers.IdAlgPwriKek, seq);

			return new RecipientInfo(new PasswordRecipientInfo(
				keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey));
		}
	}
}
