using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaParameters
    {
        public static readonly SlhDsaParameters SLH_DSA_SHA2_128s = new SlhDsaParameters("SLH-DSA-SHA2-128s",
            SlhDsaParameterSet.SLH_DSA_SHA2_128s, NistObjectIdentifiers.id_slh_dsa_sha2_128s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_128s = new SlhDsaParameters("SLH-DSA-SHAKE-128s",
            SlhDsaParameterSet.SLH_DSA_SHAKE_128s, NistObjectIdentifiers.id_slh_dsa_shake_128s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_128f = new SlhDsaParameters("SLH-DSA-SHA2-128f",
            SlhDsaParameterSet.SLH_DSA_SHA2_128f, NistObjectIdentifiers.id_slh_dsa_sha2_128f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_128f = new SlhDsaParameters("SLH-DSA-SHAKE-128f",
            SlhDsaParameterSet.SLH_DSA_SHAKE_128f, NistObjectIdentifiers.id_slh_dsa_shake_128f);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_192s = new SlhDsaParameters("SLH-DSA-SHA2-192s",
            SlhDsaParameterSet.SLH_DSA_SHA2_192s, NistObjectIdentifiers.id_slh_dsa_sha2_192s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_192s = new SlhDsaParameters("SLH-DSA-SHAKE-192s",
            SlhDsaParameterSet.SLH_DSA_SHAKE_192s, NistObjectIdentifiers.id_slh_dsa_shake_192s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_192f = new SlhDsaParameters("SLH-DSA-SHA2-192f",
            SlhDsaParameterSet.SLH_DSA_SHA2_192f, NistObjectIdentifiers.id_slh_dsa_sha2_192f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_192f = new SlhDsaParameters("SLH-DSA-SHAKE-192f",
            SlhDsaParameterSet.SLH_DSA_SHAKE_192f, NistObjectIdentifiers.id_slh_dsa_shake_192f);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_256s = new SlhDsaParameters("SLH-DSA-SHA2-256s",
            SlhDsaParameterSet.SLH_DSA_SHA2_256s, NistObjectIdentifiers.id_slh_dsa_sha2_256s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_256s = new SlhDsaParameters("SLH-DSA-SHAKE-256s",
            SlhDsaParameterSet.SLH_DSA_SHAKE_256s, NistObjectIdentifiers.id_slh_dsa_shake_256s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_256f = new SlhDsaParameters("SLH-DSA-SHA2-256f",
            SlhDsaParameterSet.SLH_DSA_SHA2_256f, NistObjectIdentifiers.id_slh_dsa_sha2_256f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_256f = new SlhDsaParameters("SLH-DSA-SHAKE-256f",
            SlhDsaParameterSet.SLH_DSA_SHAKE_256f, NistObjectIdentifiers.id_slh_dsa_shake_256f);

        internal static readonly IDictionary<string, SlhDsaParameters> ByName = CollectionUtilities.ReadOnly(
            new Dictionary<string, SlhDsaParameters>()
        {
            { SLH_DSA_SHA2_128f.Name, SLH_DSA_SHA2_128f },
            { SLH_DSA_SHA2_128s.Name, SLH_DSA_SHA2_128s },
            { SLH_DSA_SHA2_192f.Name, SLH_DSA_SHA2_192f },
            { SLH_DSA_SHA2_192s.Name, SLH_DSA_SHA2_192s },
            { SLH_DSA_SHA2_256f.Name, SLH_DSA_SHA2_256f },
            { SLH_DSA_SHA2_256s.Name, SLH_DSA_SHA2_256s },
            { SLH_DSA_SHAKE_128f.Name, SLH_DSA_SHAKE_128f },
            { SLH_DSA_SHAKE_128s.Name, SLH_DSA_SHAKE_128s },
            { SLH_DSA_SHAKE_192f.Name, SLH_DSA_SHAKE_192f },
            { SLH_DSA_SHAKE_192s.Name, SLH_DSA_SHAKE_192s },
            { SLH_DSA_SHAKE_256f.Name, SLH_DSA_SHAKE_256f },
            { SLH_DSA_SHAKE_256s.Name, SLH_DSA_SHAKE_256s },
        });

        internal static readonly IDictionary<DerObjectIdentifier, SlhDsaParameters> ByOid = CollectionUtilities.ReadOnly(
            new Dictionary<DerObjectIdentifier, SlhDsaParameters>()
        {
            { SLH_DSA_SHA2_128f.Oid, SLH_DSA_SHA2_128f },
            { SLH_DSA_SHA2_128s.Oid, SLH_DSA_SHA2_128s },
            { SLH_DSA_SHA2_192f.Oid, SLH_DSA_SHA2_192f },
            { SLH_DSA_SHA2_192s.Oid, SLH_DSA_SHA2_192s },
            { SLH_DSA_SHA2_256f.Oid, SLH_DSA_SHA2_256f },
            { SLH_DSA_SHA2_256s.Oid, SLH_DSA_SHA2_256s },
            { SLH_DSA_SHAKE_128f.Oid, SLH_DSA_SHAKE_128f },
            { SLH_DSA_SHAKE_128s.Oid, SLH_DSA_SHAKE_128s },
            { SLH_DSA_SHAKE_192f.Oid, SLH_DSA_SHAKE_192f },
            { SLH_DSA_SHAKE_192s.Oid, SLH_DSA_SHAKE_192s },
            { SLH_DSA_SHAKE_256f.Oid, SLH_DSA_SHAKE_256f },
            { SLH_DSA_SHAKE_256s.Oid, SLH_DSA_SHAKE_256s },
        });

        private readonly string m_name;
        private readonly SlhDsaParameterSet m_parameterSet;
        private readonly DerObjectIdentifier m_oid;

        private SlhDsaParameters(string name, SlhDsaParameterSet parameterSet, DerObjectIdentifier oid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_parameterSet = parameterSet ?? throw new ArgumentNullException(nameof(parameterSet));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
        }

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier PreHashOid => null;

        public SlhDsaParameterSet ParameterSet => m_parameterSet;

        public override string ToString() => Name;
    }
}
