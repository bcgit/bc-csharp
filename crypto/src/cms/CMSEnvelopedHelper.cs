using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
	// TODO[api] Make static
	internal class CmsEnvelopedHelper
	{
		internal static readonly CmsEnvelopedHelper Instance = new CmsEnvelopedHelper();

		private static readonly Dictionary<string, int> KeySizes = new Dictionary<string, int>();
		private static readonly Dictionary<string, string> Rfc3211WrapperNames = new Dictionary<string, string>();

		static CmsEnvelopedHelper()
		{
			KeySizes.Add(CmsEnvelopedGenerator.Aes128Cbc, 128);
			KeySizes.Add(CmsEnvelopedGenerator.Aes192Cbc, 192);
			KeySizes.Add(CmsEnvelopedGenerator.Aes256Cbc, 256);
            KeySizes.Add(CmsEnvelopedGenerator.Camellia128Cbc, 128);
            KeySizes.Add(CmsEnvelopedGenerator.Camellia192Cbc, 192);
            KeySizes.Add(CmsEnvelopedGenerator.Camellia256Cbc, 256);
            KeySizes.Add(CmsEnvelopedGenerator.DesCbc, 64);
            KeySizes.Add(CmsEnvelopedGenerator.DesEde3Cbc, 192);

            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes128Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes192Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes256Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia128Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia192Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia256Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.DesCbc, "DESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.DesEde3Cbc, "DESEDERFC3211WRAP");
        }

        internal static RecipientInformationStore BuildRecipientInformationStore(
			Asn1Set recipientInfos, CmsSecureReadable secureReadable)
		{
			var infos = new List<RecipientInformation>();
			for (int i = 0; i != recipientInfos.Count; i++)
			{
				RecipientInfo info = RecipientInfo.GetInstance(recipientInfos[i]);

				ReadRecipientInfo(infos, info, secureReadable);
			}
			return new RecipientInformationStore(infos);
		}

        internal int GetKeySize(string oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (!KeySizes.TryGetValue(oid, out var keySize))
                throw new ArgumentException("no key size for " + oid, nameof(oid));

            return keySize;
        }

        internal string GetRfc3211WrapperName(string oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (!Rfc3211WrapperNames.TryGetValue(oid, out var name))
                throw new ArgumentException("no name for " + oid, nameof(oid));

            return name;
        }

        private static void ReadRecipientInfo(IList<RecipientInformation> infos, RecipientInfo info,
			CmsSecureReadable secureReadable)
		{
			Asn1Encodable recipInfo = info.Info;
			if (recipInfo is KeyTransRecipientInfo keyTransRecipientInfo)
			{
				infos.Add(new KeyTransRecipientInformation(keyTransRecipientInfo, secureReadable));
			}
			else if (recipInfo is KekRecipientInfo kekRecipientInfo)
			{
				infos.Add(new KekRecipientInformation(kekRecipientInfo, secureReadable));
			}
			else if (recipInfo is KeyAgreeRecipientInfo keyAgreeRecipientInfo)
			{
				KeyAgreeRecipientInformation.ReadRecipientInfo(infos, keyAgreeRecipientInfo, secureReadable);
			}
			else if (recipInfo is PasswordRecipientInfo passwordRecipientInfo)
			{
				infos.Add(new PasswordRecipientInformation(passwordRecipientInfo, secureReadable));
			}
		}

		internal class CmsAuthenticatedSecureReadable : CmsSecureReadable
		{
			private AlgorithmIdentifier algorithm;
			private IMac mac;
			private CmsReadable readable;

			internal CmsAuthenticatedSecureReadable(AlgorithmIdentifier algorithm, CmsReadable readable)
			{
				this.algorithm = algorithm;
				this.readable = readable;
			}

			public AlgorithmIdentifier Algorithm
			{
				get { return this.algorithm; }
			}

			public object CryptoObject
			{
				get { return this.mac; }
			}

			public CmsReadable GetReadable(KeyParameter sKey)
			{
                string macAlg = this.algorithm.Algorithm.Id;
//				Asn1Object sParams = this.algorithm.Parameters.ToAsn1Object();

				try
				{
					this.mac = MacUtilities.GetMac(macAlg);

					// FIXME Support for MAC algorithm parameters similar to cipher parameters
//						ASN1Object sParams = (ASN1Object)macAlg.getParameters();
//
//						if (sParams != null && !(sParams instanceof ASN1Null))
//						{
//							AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(macAlg.getObjectId().getId(), provider);
//
//							params.init(sParams.getEncoded(), "ASN.1");
//
//							mac.init(sKey, params.getParameterSpec(IvParameterSpec.class));
//						}
//						else
					{
						mac.Init(sKey);
					}

//						Asn1Object asn1Params = asn1Enc == null ? null : asn1Enc.ToAsn1Object();
//
//						ICipherParameters cipherParameters = sKey;
//
//						if (asn1Params != null && !(asn1Params is Asn1Null))
//						{
//							cipherParameters = ParameterUtilities.GetCipherParameters(
//							macAlg.Algorithm, cipherParameters, asn1Params);
//						}
//						else
//						{
//							string alg = macAlg.Algorithm.Id;
//							if (alg.Equals(CmsEnvelopedGenerator.DesEde3Cbc)
//								|| alg.Equals(CmsEnvelopedGenerator.IdeaCbc)
//								|| alg.Equals(CmsEnvelopedGenerator.Cast5Cbc))
//							{
//								cipherParameters = new ParametersWithIV(cipherParameters, new byte[8]);
//							}
//						}
//
//						mac.Init(cipherParameters);
				}
				catch (SecurityUtilityException e)
				{
					throw new CmsException("couldn't create cipher.", e);
				}
				catch (InvalidKeyException e)
				{
					throw new CmsException("key invalid in message.", e);
				}
				catch (IOException e)
				{
					throw new CmsException("error decoding algorithm parameters.", e);
				}

				try
				{
					return new CmsProcessableInputStream(
						new TeeInputStream(
							readable.GetInputStream(),
							new MacSink(this.mac)));
				}
				catch (IOException e)
				{
					throw new CmsException("error reading content.", e);
				}
			}
		}

		internal class CmsEnvelopedSecureReadable : CmsSecureReadable
		{
			private AlgorithmIdentifier algorithm;
			private IBufferedCipher cipher;
			private CmsReadable readable;

			internal CmsEnvelopedSecureReadable(AlgorithmIdentifier algorithm, CmsReadable readable)
			{
				this.algorithm = algorithm;
				this.readable = readable;
			}

			public AlgorithmIdentifier Algorithm
			{
				get { return this.algorithm; }
			}

			public object CryptoObject
			{
				get { return this.cipher; }
			}

			public CmsReadable GetReadable(KeyParameter sKey)
			{
				try
				{
                    this.cipher = CipherUtilities.GetCipher(this.algorithm.Algorithm);

					Asn1Encodable asn1Enc = this.algorithm.Parameters;
					Asn1Object asn1Params = asn1Enc == null ? null : asn1Enc.ToAsn1Object();

					ICipherParameters cipherParameters = sKey;

					if (asn1Params != null && !(asn1Params is Asn1Null))
					{
						cipherParameters = ParameterUtilities.GetCipherParameters(
                            this.algorithm.Algorithm, cipherParameters, asn1Params);
					}
					else
					{
                        string alg = this.algorithm.Algorithm.Id;
						if (alg.Equals(CmsEnvelopedGenerator.DesEde3Cbc)
							|| alg.Equals(CmsEnvelopedGenerator.IdeaCbc)
							|| alg.Equals(CmsEnvelopedGenerator.Cast5Cbc))
						{
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
							cipherParameters = ParametersWithIV.Create<byte>(cipherParameters, 8, 0,
								(bytes, state) => bytes.Fill(state));
#else
							cipherParameters = new ParametersWithIV(cipherParameters, new byte[8]);
#endif
						}
					}

					cipher.Init(false, cipherParameters);
				}
				catch (SecurityUtilityException e)
				{
					throw new CmsException("couldn't create cipher.", e);
				}
				catch (InvalidKeyException e)
				{
					throw new CmsException("key invalid in message.", e);
				}
				catch (IOException e)
				{
					throw new CmsException("error decoding algorithm parameters.", e);
				}

				try
				{
					return new CmsProcessableInputStream(
						new CipherStream(readable.GetInputStream(), cipher, null));
				}
				catch (IOException e)
				{
					throw new CmsException("error reading content.", e);
				}
			}
		}
	}
}
