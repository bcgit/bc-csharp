using System;

namespace Org.BouncyCastle.Asn1.Nsri
{
    /// <summary>Object identifiers for NSRI, the Korean National Security Research Institute.</summary>
    // TODO[api] Make static
    public sealed class NsriObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.410.200046</c>.</summary>
        public static readonly DerObjectIdentifier nsri = new DerObjectIdentifier("1.2.410.200046");

        /// <summary>The object identifier <c>1.2.410.200046.1</c>.</summary>
        public static readonly DerObjectIdentifier id_algorithm = nsri.Branch("1");

        /// <summary>The object identifier <c>1.2.410.200046.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_sea = id_algorithm.Branch("1");
        /// <summary>The object identifier <c>1.2.410.200046.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_pad = id_algorithm.Branch("2");

        /// <summary>The object identifier <c>1.2.410.200046.1.0</c>.</summary>
        public static readonly DerObjectIdentifier id_pad_null = id_algorithm.Branch("0");
        /// <summary>The object identifier <c>1.2.410.200046.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_pad_1 = id_algorithm.Branch("1");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_ecb = id_sea.Branch("1");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_cbc = id_sea.Branch("2");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_cfb = id_sea.Branch("3");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.4</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_ofb = id_sea.Branch("4");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.5</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_ctr = id_sea.Branch("5");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.6</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_ecb = id_sea.Branch("6");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.7</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_cbc = id_sea.Branch("7");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.8</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_cfb = id_sea.Branch("8");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.9</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_ofb = id_sea.Branch("9");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.10</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_ctr = id_sea.Branch("10");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.11</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_ecb = id_sea.Branch("11");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.12</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_cbc = id_sea.Branch("12");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.13</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_cfb = id_sea.Branch("13");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.14</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_ofb = id_sea.Branch("14");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.15</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_ctr = id_sea.Branch("15");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.21</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_cmac = id_sea.Branch("21");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.22</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_cmac = id_sea.Branch("22");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.23</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_cmac = id_sea.Branch("23");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.31</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_ocb2 = id_sea.Branch("31");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.32</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_ocb2 = id_sea.Branch("32");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.33</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_ocb2 = id_sea.Branch("33");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.34</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_gcm = id_sea.Branch("34");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.35</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_gcm = id_sea.Branch("35");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.36</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_gcm = id_sea.Branch("36");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.37</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_ccm = id_sea.Branch("37");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.38</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_ccm = id_sea.Branch("38");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.39</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_ccm = id_sea.Branch("39");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.40</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_kw = id_sea.Branch("40");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.41</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_kw = id_sea.Branch("41");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.42</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_kw = id_sea.Branch("42");

        /// <summary>The object identifier <c>1.2.410.200046.1.1.43</c>.</summary>
        public static readonly DerObjectIdentifier id_aria128_kwp = id_sea.Branch("43");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.44</c>.</summary>
        public static readonly DerObjectIdentifier id_aria192_kwp = id_sea.Branch("44");
        /// <summary>The object identifier <c>1.2.410.200046.1.1.45</c>.</summary>
        public static readonly DerObjectIdentifier id_aria256_kwp = id_sea.Branch("45");
    }
}
