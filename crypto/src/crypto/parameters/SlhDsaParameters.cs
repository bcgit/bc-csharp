using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaParameters
    {
        public static readonly SlhDsaParameters slh_dsa_sha2_128s = new SlhDsaParameters("SLH-DSA-SHA2-128S",
            SlhDsaParameterSet.slh_dsa_sha2_128s, NistObjectIdentifiers.id_slh_dsa_sha2_128s, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_128s = new SlhDsaParameters("SLH-DSA-SHAKE-128s",
            SlhDsaParameterSet.slh_dsa_shake_128s, NistObjectIdentifiers.id_slh_dsa_shake_128s, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_128f = new SlhDsaParameters("SLH-DSA-SHA2-128F",
            SlhDsaParameterSet.slh_dsa_sha2_128f, NistObjectIdentifiers.id_slh_dsa_sha2_128f, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_128f = new SlhDsaParameters("SLH-DSA-SHAKE-128F",
            SlhDsaParameterSet.slh_dsa_shake_128f, NistObjectIdentifiers.id_slh_dsa_shake_128f, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_192s = new SlhDsaParameters("SLH-DSA-SHA2-192S",
            SlhDsaParameterSet.slh_dsa_sha2_192s, NistObjectIdentifiers.id_slh_dsa_sha2_192s, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_192s = new SlhDsaParameters("SLH-DSA-SHAKE-192S",
            SlhDsaParameterSet.slh_dsa_shake_192s, NistObjectIdentifiers.id_slh_dsa_shake_192s, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_192f = new SlhDsaParameters("SLH-DSA-SHA2-192F",
            SlhDsaParameterSet.slh_dsa_sha2_192f, NistObjectIdentifiers.id_slh_dsa_sha2_192f, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_192f = new SlhDsaParameters("SLH-DSA-SHAKE-192F",
            SlhDsaParameterSet.slh_dsa_shake_192f, NistObjectIdentifiers.id_slh_dsa_shake_192f, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_256s = new SlhDsaParameters("SLH-DSA-SHA2-256S",
            SlhDsaParameterSet.slh_dsa_sha2_256s, NistObjectIdentifiers.id_slh_dsa_sha2_256s, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_256s = new SlhDsaParameters("SLH-DSA-SHAKE-256S",
            SlhDsaParameterSet.slh_dsa_shake_256s, NistObjectIdentifiers.id_slh_dsa_shake_256s, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_256f = new SlhDsaParameters("SLH-DSA-SHA2-256F",
            SlhDsaParameterSet.slh_dsa_sha2_256f, NistObjectIdentifiers.id_slh_dsa_sha2_256f, preHashOid: null);
        public static readonly SlhDsaParameters slh_dsa_shake_256f = new SlhDsaParameters("SLH-DSA-SHAKE-256F",
            SlhDsaParameterSet.slh_dsa_shake_256f, NistObjectIdentifiers.id_slh_dsa_shake_256f, preHashOid: null);

        public static readonly SlhDsaParameters slh_dsa_sha2_128s_with_sha256 = new SlhDsaParameters(
            "SLH-DSA-SHA2-128S-WITH-SHA256", SlhDsaParameterSet.slh_dsa_sha2_128s,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, NistObjectIdentifiers.IdSha256);
        public static readonly SlhDsaParameters slh_dsa_shake_128s_with_shake128 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-128S-WITH-SHAKE128", SlhDsaParameterSet.slh_dsa_shake_128s,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, NistObjectIdentifiers.IdShake128);

        public static readonly SlhDsaParameters slh_dsa_sha2_128f_with_sha256 = new SlhDsaParameters(
            "SLH-DSA-SHA2-128F-WITH-SHA256", SlhDsaParameterSet.slh_dsa_sha2_128f,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, NistObjectIdentifiers.IdSha256);
        public static readonly SlhDsaParameters slh_dsa_shake_128f_with_shake128 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-128F-WITH-SHAKE128", SlhDsaParameterSet.slh_dsa_shake_128f,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, NistObjectIdentifiers.IdShake128);

        public static readonly SlhDsaParameters slh_dsa_sha2_192s_with_sha512 = new SlhDsaParameters(
            "SLH-DSA-SHA2-192S-WITH-SHA512", SlhDsaParameterSet.slh_dsa_sha2_192s,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, NistObjectIdentifiers.IdSha512);
        public static readonly SlhDsaParameters slh_dsa_shake_192s_with_shake256 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-192S-WITH-SHAKE256", SlhDsaParameterSet.slh_dsa_shake_192s,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, NistObjectIdentifiers.IdShake256);

        public static readonly SlhDsaParameters slh_dsa_sha2_192f_with_sha512 = new SlhDsaParameters(
            "SLH-DSA-SHA2-192F-WITH-SHA512", SlhDsaParameterSet.slh_dsa_sha2_192f,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, NistObjectIdentifiers.IdSha512);
        public static readonly SlhDsaParameters slh_dsa_shake_192f_with_shake256 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-192F-WITH-SHAKE256", SlhDsaParameterSet.slh_dsa_shake_192f,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, NistObjectIdentifiers.IdShake256);

        public static readonly SlhDsaParameters slh_dsa_sha2_256s_with_sha512 = new SlhDsaParameters(
            "SLH-DSA-SHA2-256S-WITH-SHA512", SlhDsaParameterSet.slh_dsa_sha2_256s,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, NistObjectIdentifiers.IdSha512);
        public static readonly SlhDsaParameters slh_dsa_shake_256s_with_shake256 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-256S-WITH-SHAKE256", SlhDsaParameterSet.slh_dsa_shake_256s,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, NistObjectIdentifiers.IdShake256);

        public static readonly SlhDsaParameters slh_dsa_sha2_256f_with_sha512 = new SlhDsaParameters(
            "SLH-DSA-SHA2-256F-WITH-SHA512", SlhDsaParameterSet.slh_dsa_sha2_256f,
            NistObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, NistObjectIdentifiers.IdSha512);
        public static readonly SlhDsaParameters slh_dsa_shake_256f_with_shake256 = new SlhDsaParameters(
            "SLH-DSA-SHAKE-256F-WITH-SHAKE256", SlhDsaParameterSet.slh_dsa_shake_256f,
            NistObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, NistObjectIdentifiers.IdShake256);

        internal static readonly IDictionary<string, SlhDsaParameters> ByName = CollectionUtilities.ReadOnly(
            new Dictionary<string, SlhDsaParameters>()
        {
            { slh_dsa_sha2_128f.Name, slh_dsa_sha2_128f },
            { slh_dsa_sha2_128f_with_sha256.Name, slh_dsa_sha2_128f_with_sha256 },
            { slh_dsa_sha2_128s.Name, slh_dsa_sha2_128s },
            { slh_dsa_sha2_128s_with_sha256.Name, slh_dsa_sha2_128s_with_sha256 },
            { slh_dsa_sha2_192f.Name, slh_dsa_sha2_192f },
            { slh_dsa_sha2_192f_with_sha512.Name, slh_dsa_sha2_192f_with_sha512 },
            { slh_dsa_sha2_192s.Name, slh_dsa_sha2_192s },
            { slh_dsa_sha2_192s_with_sha512.Name, slh_dsa_sha2_192s_with_sha512 },
            { slh_dsa_sha2_256f.Name, slh_dsa_sha2_256f },
            { slh_dsa_sha2_256f_with_sha512.Name, slh_dsa_sha2_256f_with_sha512 },
            { slh_dsa_sha2_256s.Name, slh_dsa_sha2_256s },
            { slh_dsa_sha2_256s_with_sha512.Name, slh_dsa_sha2_256s_with_sha512 },
            { slh_dsa_shake_128f.Name, slh_dsa_shake_128f },
            { slh_dsa_shake_128f_with_shake128.Name, slh_dsa_shake_128f_with_shake128 },
            { slh_dsa_shake_128s.Name, slh_dsa_shake_128s },
            { slh_dsa_shake_128s_with_shake128.Name, slh_dsa_shake_128s_with_shake128 },
            { slh_dsa_shake_192f.Name, slh_dsa_shake_192f },
            { slh_dsa_shake_192f_with_shake256.Name, slh_dsa_shake_192f_with_shake256 },
            { slh_dsa_shake_192s.Name, slh_dsa_shake_192s },
            { slh_dsa_shake_192s_with_shake256.Name, slh_dsa_shake_192s_with_shake256 },
            { slh_dsa_shake_256f.Name, slh_dsa_shake_256f },
            { slh_dsa_shake_256f_with_shake256.Name, slh_dsa_shake_256f_with_shake256 },
            { slh_dsa_shake_256s.Name, slh_dsa_shake_256s },
            { slh_dsa_shake_256s_with_shake256.Name, slh_dsa_shake_256s_with_shake256 },
        });

        internal static readonly IDictionary<DerObjectIdentifier, SlhDsaParameters> ByOid = CollectionUtilities.ReadOnly(
            new Dictionary<DerObjectIdentifier, SlhDsaParameters>()
        {
            { slh_dsa_sha2_128f.Oid, slh_dsa_sha2_128f },
            { slh_dsa_sha2_128f_with_sha256.Oid, slh_dsa_sha2_128f_with_sha256 },
            { slh_dsa_sha2_128s.Oid, slh_dsa_sha2_128s },
            { slh_dsa_sha2_128s_with_sha256.Oid, slh_dsa_sha2_128s_with_sha256 },
            { slh_dsa_sha2_192f.Oid, slh_dsa_sha2_192f },
            { slh_dsa_sha2_192f_with_sha512.Oid, slh_dsa_sha2_192f_with_sha512 },
            { slh_dsa_sha2_192s.Oid, slh_dsa_sha2_192s },
            { slh_dsa_sha2_192s_with_sha512.Oid, slh_dsa_sha2_192s_with_sha512 },
            { slh_dsa_sha2_256f.Oid, slh_dsa_sha2_256f },
            { slh_dsa_sha2_256f_with_sha512.Oid, slh_dsa_sha2_256f_with_sha512 },
            { slh_dsa_sha2_256s.Oid, slh_dsa_sha2_256s },
            { slh_dsa_sha2_256s_with_sha512.Oid, slh_dsa_sha2_256s_with_sha512 },
            { slh_dsa_shake_128f.Oid, slh_dsa_shake_128f },
            { slh_dsa_shake_128f_with_shake128.Oid, slh_dsa_shake_128f_with_shake128 },
            { slh_dsa_shake_128s.Oid, slh_dsa_shake_128s },
            { slh_dsa_shake_128s_with_shake128.Oid, slh_dsa_shake_128s_with_shake128 },
            { slh_dsa_shake_192f.Oid, slh_dsa_shake_192f },
            { slh_dsa_shake_192f_with_shake256.Oid, slh_dsa_shake_192f_with_shake256 },
            { slh_dsa_shake_192s.Oid, slh_dsa_shake_192s },
            { slh_dsa_shake_192s_with_shake256.Oid, slh_dsa_shake_192s_with_shake256 },
            { slh_dsa_shake_256f.Oid, slh_dsa_shake_256f },
            { slh_dsa_shake_256f_with_shake256.Oid, slh_dsa_shake_256f_with_shake256 },
            { slh_dsa_shake_256s.Oid, slh_dsa_shake_256s },
            { slh_dsa_shake_256s_with_shake256.Oid, slh_dsa_shake_256s_with_shake256 },
        });

        private readonly string m_name;
        private readonly SlhDsaParameterSet m_parameterSet;
        private readonly DerObjectIdentifier m_oid;
        private readonly DerObjectIdentifier m_preHashOid;

        private SlhDsaParameters(string name, SlhDsaParameterSet parameterSet, DerObjectIdentifier oid,
            DerObjectIdentifier preHashOid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_parameterSet = parameterSet ?? throw new ArgumentNullException(nameof(parameterSet));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
            m_preHashOid = preHashOid;
        }

        public bool IsPreHash => m_preHashOid != null;

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier PreHashOid => m_preHashOid;

        public SlhDsaParameterSet ParameterSet => m_parameterSet;

        public override string ToString() => Name;
    }
}
