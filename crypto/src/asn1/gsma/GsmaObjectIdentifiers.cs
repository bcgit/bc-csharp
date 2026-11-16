namespace Org.BouncyCastle.Asn1.Gsma
{
    /// <summary>Object identifiers for the GSMA.</summary>
    public static class GsmaObjectIdentifiers
    {
        /// <summary>The object identifier <c>2.23.146</c>.</summary>
        public static readonly DerObjectIdentifier id_gsma = new DerObjectIdentifier("2.23.146");

        /// <summary>The object identifier <c>2.23.146.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp = id_gsma.Branch("1");

        /// <summary>The object identifier <c>2.23.146.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_cert_objects = id_rsp.Branch("2");

        /// <summary>The object identifier <c>2.23.146.1.2.0</c>.</summary>
        public static readonly DerObjectIdentifier id_rspExt = id_rsp_cert_objects.Branch("0");

        /// <summary>The object identifier <c>2.23.146.1.2.0.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_expDate = id_rspExt.Branch("1");
        /// <summary>The object identifier <c>2.23.146.1.2.0.2</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_totalPartialCrlNumber = id_rspExt.Branch("2");
        /// <summary>The object identifier <c>2.23.146.1.2.0.3</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_partialCrlNumber = id_rspExt.Branch("3");

        /// <summary>The object identifier <c>2.23.146.1.2.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole = id_rsp_cert_objects.Branch("1");

        /// <summary>The object identifier <c>2.23.146.1.2.1.0</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_ci = id_rspRole.Branch("0");
        /// <summary>The object identifier <c>2.23.146.1.2.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_euicc = id_rspRole.Branch("1");
        /// <summary>The object identifier <c>2.23.146.1.2.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_eum = id_rspRole.Branch("2");
        /// <summary>The object identifier <c>2.23.146.1.2.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_dp_tls = id_rspRole.Branch("3");
        /// <summary>The object identifier <c>2.23.146.1.2.1.4</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_dp_auth = id_rspRole.Branch("4");
        /// <summary>The object identifier <c>2.23.146.1.2.1.5</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_dp_pb = id_rspRole.Branch("5");
        /// <summary>The object identifier <c>2.23.146.1.2.1.6</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_ds_tls = id_rspRole.Branch("6");
        /// <summary>The object identifier <c>2.23.146.1.2.1.7</c>.</summary>
        public static readonly DerObjectIdentifier id_rspRole_ds_auth = id_rspRole.Branch("7");

        /// <summary>The object identifier <c>2.23.146.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_metadata = id_rsp.Branch("3");

        /// <summary>The object identifier <c>2.23.146.1.3.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_metadata_serviceSpecificOIDs = id_rsp_metadata.Branch("1");

        /// <summary>The object identifier <c>2.23.146.1.3.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_rsp_metadata_activationCodeRetrievalInfo =
            id_rsp_metadata_serviceSpecificOIDs.Branch("1");
    }
}
