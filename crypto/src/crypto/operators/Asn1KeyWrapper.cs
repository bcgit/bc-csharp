using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1KeyWrapper : IKeyWrapper
    {
        private string algorithm;
        private IKeyWrapper wrapper;

        public Asn1KeyWrapper(string algorithm, X509Certificate cert)
        {
            this.algorithm = algorithm;
            wrapper = KeyWrapperUtil.WrapperForName(algorithm, cert.GetPublicKey());
        }

        public object AlgorithmDetails
        {
            get { return wrapper.AlgorithmDetails; }
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return wrapper.Wrap(keyData);
        }
    }

    internal class KeyWrapperUtil
    {
        //
        // Provider 
        //
        private static readonly IDictionary providerMap = Platform.CreateHashtable();

        static KeyWrapperUtil()
        {
            providerMap["RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha1_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha224_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha256_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha384_Oaep);
            providerMap["RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"] = new WrapperCreator(RsaOaepWrapper.Rsa_Sha512_Oaep);
        }

        public static IKeyWrapper WrapperForName(string algorithm, ICipherParameters parameters)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];

            if (provider == null)
            {
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyWrapper");
            }

            return (IKeyWrapper)provider.createWrapper(true, parameters);
        }

        public static IKeyUnwrapper UnwrapperForName(string algorithm, ICipherParameters parameters)
        {
            WrapperProvider provider = (WrapperProvider)providerMap[Strings.ToUpperCase(algorithm)];
            if (provider == null)
            {
                throw new ArgumentException("could not resolve " + algorithm + " to a KeyUnwrapper");
            }

            return (IKeyUnwrapper)provider.createWrapper(false, parameters);
        }
    }

    internal delegate object WrapperCreatorDelegate(bool forWrapping, ICipherParameters parameters);

    /// <summary>
    /// Wraps delegate and implements the WrapperProvider Interface.
    /// </summary>
    internal class WrapperCreator : WrapperProvider
    {
        private readonly WrapperCreatorDelegate creator;

        public WrapperCreator(WrapperCreatorDelegate creator)
        {
            this.creator = creator;
        }

        public object createWrapper(bool forWrapping, ICipherParameters parameters)
        {
            return this.creator.Invoke(forWrapping, parameters);
        }
    }

    internal interface WrapperProvider
    {
        object createWrapper(bool forWrapping, ICipherParameters parameters);
    }

    internal class RsaOaepWrapper : IKeyWrapper, IKeyUnwrapper
    {
        internal static object Rsa_Sha1_Oaep(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, OiwObjectIdentifiers.IdSha1);
        }

        internal static object Rsa_Sha224_Oaep(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, NistObjectIdentifiers.IdSha224);
        }

        internal static object Rsa_Sha256_Oaep(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, NistObjectIdentifiers.IdSha256);
        }

        internal static object Rsa_Sha384_Oaep(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, NistObjectIdentifiers.IdSha384);
        }

        internal static object Rsa_Sha512_Oaep(bool forWrapping, ICipherParameters parameters)
        {
            return new RsaOaepWrapper(forWrapping, parameters, NistObjectIdentifiers.IdSha512);
        }

        private readonly AlgorithmIdentifier algId;
        private readonly IAsymmetricBlockCipher engine;

        public RsaOaepWrapper(bool forWrapping, ICipherParameters parameters, DerObjectIdentifier digestOid)
        {
            AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(digestOid, DerNull.Instance);

            this.algId = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.IdRsaesOaep,
                new RsaesOaepParameters(
                    digestAlgId,
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digestAlgId),
                    RsaesOaepParameters.DefaultPSourceAlgorithm));
            this.engine = new OaepEncoding(new RsaBlindedEngine(), DigestUtilities.GetDigest(digestOid) );
            this.engine.Init(forWrapping, parameters);
        }

        public object AlgorithmDetails
        {
            get
            {
                return algId;
            }
        }

        public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
        {
            return new SimpleBlockResult(engine.ProcessBlock(cipherText, offset, length));
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return new SimpleBlockResult(engine.ProcessBlock(keyData, 0, keyData.Length));
        }
    }
}
