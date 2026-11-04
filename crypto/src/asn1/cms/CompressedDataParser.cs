using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
    * RFC 3274 - CMS Compressed Data.
    * <pre>
    * CompressedData ::= SEQUENCE {
    *  version CMSVersion,
    *  compressionAlgorithm CompressionAlgorithmIdentifier,
    *  encapContentInfo EncapsulatedContentInfo
    * }
    * </pre>
    */
    public class CompressedDataParser
    {
        private DerInteger _version;
        private AlgorithmIdentifier _compressionAlgorithm;
        private ContentInfoParser _encapContentInfo;

        /// <summary>Create a new <see cref="CompressedDataParser"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        public CompressedDataParser(
            Asn1SequenceParser seq)
        {
            this._version = (DerInteger)seq.ReadObject();
            this._compressionAlgorithm = AlgorithmIdentifier.GetInstance(seq.ReadObject().ToAsn1Object());
            this._encapContentInfo = new ContentInfoParser((Asn1SequenceParser)seq.ReadObject());
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version
        {
            get { return _version; }
        }

        /// <summary>Gets the compression algorithm identifier.</summary>
        public AlgorithmIdentifier CompressionAlgorithmIdentifier
        {
            get { return _compressionAlgorithm; }
        }

        /// <summary>Return the encap content info.</summary>
        public ContentInfoParser GetEncapContentInfo()
        {
            return _encapContentInfo;
        }
    }
}
