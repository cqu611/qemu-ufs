/* Ufs Host Controller interface */
#ifndef HW_NVME_H
#define HW_NVME_H
#include <qemu/bitops.h>


enum {
    TASK_REQ_UPIU_SIZE_DWORDS   = 8,
    TASK_RSP_UPIU_SIZE_DWORDS   = 8,
    ALIGNED_UPIU_SIZE       = 512,
};

typedef struct UfsRwCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    dsmgmt;
    uint32_t    reftag;
    uint16_t    apptag;
    uint16_t    appmask;
} UfsRwCmd;


/*UPIU format spec ufs2.1	not available	aran-lq*/
typedef struct CmdUPIU {
    uint8_t     opcode;
    uint8_t     fuse;
    uint16_t    cid;
    uint32_t    lunid;				//LUN ID		aran-lq
    uint64_t    res1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
} CmdUPIU;

typedef struct UfsBar {
    /* Host Capabilities */
    uint32_t    cap;
    uint32_t    rsvd0;		
    uint32_t    vs;	
    uint32_t    rsvd1;		
    uint32_t    hcdid;		
    uint32_t    hcpmid;		
    uint32_t    ahit;			
    uint32_t    rsvd2;

    /* Operation and Runtime */
    uint32_t    is;		
    uint32_t    ie;		
    uint64_t    rsvd3;		
    uint32_t    hcs;					
    uint32_t    hce;		
    uint32_t    uecpa;		
    uint32_t    uecdl;
    uint32_t    uecn;
    uint32_t    uect;
    uint32_t    uecdme;
    uint32_t    utriacr;

    /* UTP Transfer */
    uint32_t    utrlba;
    uint32_t    utrlbau;
    uint32_t    utrldbr;
    uint32_t    utrlclr;
    uint32_t	utrlrsr;
    uint32_t    utrlcnr;
    uint64_t    rsvd4;

    /* UTP Task Management */
    uint32_t    utmrlba;
    uint32_t    utmrlbau;
    uint32_t    utmrldbr;
    uint32_t    utmrlclr;
    uint32_t    utmrlrsr;
    uint32_t    rsvd5[3];

    /* UIC Command */
    uint32_t    uiccmd;
    uint32_t    ucmdarg1;
    uint32_t    ucmdarg2;
    uint32_t    ucmdarg3;
    uint64_t    rsvd6[2];

    /* UMA */
    uint64_t    rsvd7[2];

    /* Crypto */
    uint32_t    ccap;

} UfsBar;		

#define UFS_MASK(mask, offset)      ((mask) << (offset))
#define UFS_BIT(x)  (1L << (x))

enum UfsCapShift {
    CAP_NUTRS_SHIFT      = 0,
    CAP_NORTT_SHIFT      = 8,
    CAP_NUTMRS_SHIFT     = 16,
    CAP_AUTOH8_SHIFT     = 23,
    CAP_64AS_SHIFT       = 24,
    CAP_OODDS_SHIFT      = 25,    
    CAP_UICDMETMS_SHIFT  = 26,
    CAP_CS_SHIFT         = 28,
};

enum UfsCapMask {
    CAP_NUTRS_MASK          = 0x1F,
	CAP_NORTT_MASK          = 0xFF,
    CAP_NUTMRS_MASK         = 0x7,
    CAP_64AS_MASK          = 0x1,
    CAP_OODDS_MAKS          = 0x1,
    CAP_UICDMETMS_MASK      = 0x1,
};

#define UFS_CAP_SET_NUTRS(cap, val)   (cap |= (uint32_t)(val & CAP_NUTRS_MASK ) \
		<< CAP_NUTRS_SHIFT)

#define UFS_CAP_SET_NUTMRS(cap, val)   (cap |= (uint32_t)(val & CAP_NUTMRS_MASK ) \
		<< CAP_NUTMRS_SHIFT)

#define UFS_CAP_SET_NORTT(cap, val)   (cap |= (uint32_t)(val & CAP_NORTT_MASK ) \
		<< CAP_NORTT_SHIFT)

#define UFS_CAP_SET_64AS(cap, val)   (cap |= (uint32_t)(val & CAP_64AS_MASK ) \
		<< CAP_64AS_SHIFT)
enum UfsVerShift {
    VER_VS_SHIFT      = 0,
    VER_MNR_SHIFT     = 4,
    VER_MJR_SHIFT     = 8,
};

enum UfsVerMask {
    VER_VS_MASK          = 0xF,
    VER_MNR_MASK         = 0xF,
    VER_MJR_MASK         = 0xFF,
};

enum UfsMidShift {
    MID_MIC_SHIFT      = 0,
    MID_BI_SHIFT     = 8,
};

enum UfsMidMask {
    MID_MIC_MASK      = 0xFF,
    MID_BI_MASK       = 0xFF,
};

enum UfsIsShift {
    IS_UTRCS_SHIFT      = 0,
    IS_UDEPRI_SHIFT      = 1,
    IS_UE_SHIFT         = 2,
    IS_UTMS_SHIFT       = 3,
    IS_UPMS_SHIFT      = 4,
    IS_UHXS_SHIFT      = 5,
    IS_UHES_SHIFT      = 6,
    IS_ULLS_SHIFT      = 7,
    IS_ULSS_SHIFT      =8,
    IS_UTMRCS_SHIFT    = 9,
    IS_UCCS_SHIFT      = 10,
    IS_DFES_SHIFT      = 11,
    IS_HCFES_SHIFT      = 16,
    IS_SBFES_SHIFT      = 17,
};

enum UfsIsMask {
    IS_UTRCS_MASK      = 0x1,
    IS_UDEPRI_MASK      =0x1,
    IS_UE_MASK         =0x1,
    IS_UTMS_MASK       =0x1,
    IS_UPMS_MASK      = 0x1,
    IS_UHXS_MASK      = 0x1,
    IS_UHES_MASK      = 0x1,
    IS_ULLS_MASK      = 0x1,
    IS_ULSS_MASK      =0x1,
    IS_UTMRCS_MASK    = 0x1,
    IS_UCCS_MASK      = 0x1,
    IS_DFES_MASK      = 0x1,
    IS_HCFES_MASK      =0x1,
    IS_SBFES_MASK      =0x1,
};

enum UfsHcsShift {
    HCS_DP_SHIFT           = 0,
    HCS_UTRLRDY_SHIFT      = 1,
    HCS_UTMRLRDY_SHIFT     = 2,
    HCS_UCRDY_SHIFT     = 3,
    HCS_UPMCRS_SHIFT     = 8,
    HCS_UTPES_SHIFT     = 12,
};

enum UFsHcs {
    UFS_UICCMD_READY         = 1 << HCS_UCRDY_SHIFT,
	UFS_DP_READY         = 1 << HCS_DP_SHIFT,
};

enum UfsHcsMask {
    HCS_DP_MASK           = 0x1,
    HCS_UTRLRDY_MASK      = 0x1,
    HCS_UTMRLRDY_MASK     = 0x1,
    HCS_UCRDY_MASK     = 0x1,
    HCS_UPMCRS_MASK     = 0x7,
    HCS_UTPES_MASK     = 0xFFFFF,
};

#define UFS_HCE_EN(cap)  (((cap) >> HCE_HCE_SHIFT)   & HCE_HCE_MASK)
#define UFS_HCS_UCRDY_EN(hcs) ( hcs = 0x00000008)

/* UIC Power Mode Change Request Status */
enum {
    PWR_OK      = 0x0,
    PWR_LOCAL   = 0x01,
    PWR_REMOTE  = 0x02,
    PWR_BUSY    = 0x03,
    PWR_ERROR_CAP   = 0x04,
    PWR_FATAL_ERROR = 0x05,
};

enum UfsHceShift {
    HCE_HCE_SHIFT      = 0,
    HCE_CGE_SHIFT      = 1,
};

enum UfsHceMask {
    HCE_HCE_MASK      = 0x1,
    HCE_CGE_MASK      = 0x1,
};

enum UfsUecpaShift {
    UECPA_EC_SHIFT    =  0,
    UECPA_ERR_SHIFT   = 31,
};

enum UfsUecpaMask {
    UECPA_EC_MASK    = 0x1F,
    UECPA_ERR_MASK   = 0x1,
};

enum UfsUecdlShift {
    UECDL_EC_SHIFT    =  0,
    UECDL_ERR_SHIFT   = 31,
};

enum UfsUecdlMask {
    UECDL_EC_MASK    = 0x7FFF,
    UECDL_ERR_MASK   = 0x1,
};

enum UfsUecnShift {
    UECN_EC_SHIFT    =  0,
    UECN_ERR_SHIFT   = 31,
};

enum UfsUecnMask {
    UECN_EC_MASK    = 0x7,
    UECN_ERR_MASK   = 0x1,
};

enum UfsUectShift {
    UECT_EC_SHIFT    =  0,
    UECT_ERR_SHIFT   = 31,
};

enum UfsUectMask {
    UECT_EC_MASK    = 0x7F,
    UECT_ERR_MASK   = 0x1,
};

enum UfsUecdmeShift {
    UECDME_EC_SHIFT    =  0,
    UECDME_ERR_SHIFT   = 31,
};

enum UfsUecdmeMask {
    UECDME_EC_MASK    =  0,
    UECDME_ERR_MASK   = 31,
};

enum UfsUtriacrShift{
    UTRIACR_IATOVAL_SHIFT   = 0,
    UTRIACR_IACTH_SHIFT   = 8,
    UTRIACR_CTR_SHIFT   = 16,
    UTRIACR_IASB_SHIFT   = 20,
    UTRIACR_IAPWEN_SHIFT   = 24,
    UTRIACR_IAEN_SHIFT   = 31,
};

enum UfsUtriacrMask{
    UTRIACR_IATOVAL_MASK   = 0xFF,
    UTRIACR_IACTH_MASK   = 0x1F,
    UTRIACR_CTR_MASK   = 0x1,
    UTRIACR_IASB_MASK   = 0x1,
    UTRIACR_IAPWEN_MASK   = 0x1,
    UTRIACR_IAEN_MASK   = 0x1,
};

/* UTP Transfer Request Registers */

enum UfsUtrlbaShift{
    UTRLBA_UTRLBA_SHIFT   = 10,
};

enum UfsUtrlbaMask{
    UTRLBA_UTRLBA_MASK   = 0x3fffff,
};

enum UfsUtrlbauShift{
    UTRLBA_UTRLBAU_SHIFT   = 0,
};

enum UfsUtrlbauMask{
    UTRLBA_UTRLBAU_MASK   = 0xffffffff,
};

enum UfsUtrldbrShift{
    UTRLDBR_UTRLDBR_SHIFT   = 0,
};

enum UfsUtrldbrMask{
    UTRLDBR_UTRLDBR_MASK   = 0xffffffff,
};

enum UfsUtrlclrShift{
    UTRLCLR_UTRLCLR_SHIFT = 0,
};

enum UfsUtrlclrMask{
    UTRLCLR_UTRLCLR_MASK = 0xffffffff,
};

/* UTRLRSR - UTP Transfer Request Run-Stop Register 60h */
enum UfsUtrlrsrShift{
    UTRLRSR_UTRLRSR_SHIFT = 0,
};

enum UfsUtrlrsrMask{
    UTRLRS_UTRLRSR_MASK = 0x1,
};

enum UfsUtrlcnrShift{
    UTRLCNR_UTRLCNR_SHIFT = 0,
};

enum UfsUtrlcnrMask{
    UTRLCNR_UTRLCNR_MASK = 0xffffffff,
};

/* UTP Task Management Request List Base Address */

enum UfsUtmrlbaShift{
    UTRLBA_UTMRLBA_SHIFT   = 10,
};

enum UfsUtmrlbaMask{
    UTRLBA_UTMRLBA_MASK   = 0x3fffff,
};

enum UfsUtmrlbauShift{
    UTRLBA_UTMRLBAU_SHIFT   = 0,
};

enum UfsUtmrlbauMask{
    UTRLBA_UTRMLBAU_MASK   = 0xffffffff,
};

/* UTP Task Management Request List Door Bell Register */

enum UfsUtmrldbrShift{
    UTRLDBR_UTMRLDBR_SHIFT   = 0,
};

enum UfsUtmrldbrMask{
    UTRLDBR_UTMRLDBR_MASK   = 0xff,
};

enum UfsUtmrlclrShift{
    UTMRLCLR_UTMRLCLR_SHIFT = 0,
};

enum UfsUtmrlclrMask{
    UTMRLCLR_UTMRLCLR_MASK = 0xff,
};

enum UfsUtmrlrsrShift{
    UTMRLRSR_UTMRLRSR_SHIFT = 0,
};

enum UfsUtmrlrsrMask{
    UTMRLRSR_UTMRLRSR_MASK = 0x1,
};

/* UIC Command Registers */
enum uic_cmd_dme {
    UIC_CMD_DME_GET         = 0x01,
    UIC_CMD_DME_SET         = 0x02,
    UIC_CMD_DME_PEER_GET        = 0x03,
    UIC_CMD_DME_PEER_SET        = 0x04,
    UIC_CMD_DME_POWERON     = 0x10,
    UIC_CMD_DME_POWEROFF        = 0x11,
    UIC_CMD_DME_ENABLE      = 0x12,
    UIC_CMD_DME_RESET       = 0x14,
    UIC_CMD_DME_END_PT_RST      = 0x15,
    UIC_CMD_DME_LINK_STARTUP    = 0x16,
    UIC_CMD_DME_HIBER_ENTER     = 0x17,
    UIC_CMD_DME_HIBER_EXIT      = 0x18,
    UIC_CMD_DME_TEST_MODE       = 0x1A,
};

typedef struct UfsRangeType {
    uint8_t     type;
    uint8_t     attributes;
    uint8_t     rsvd2[14];
    uint64_t    slba;
    uint64_t    nlb;
    uint8_t     guid[16];
    uint8_t     rsvd48[16];
} UfsRangeType;

#define COMMAND_OPCODE_MASK     0xFF
#define GEN_SELECTOR_INDEX_MASK     0xFFFF

#define MIB_ATTRIBUTE_MASK      UFS_MASK(0xFFFF, 16)
#define RESET_LEVEL         0xFF

#define ATTR_SET_TYPE_MASK      UFS_MASK(0xFF, 16)
#define CONFIG_RESULT_CODE_MASK     0xFF
#define GENERIC_ERROR_CODE_MASK     0xFF

/* GenSelectorIndex calculation macros for M-PHY attributes */
#define UIC_ARG_MPHY_TX_GEN_SEL_INDEX(lane) (lane)
#define UIC_ARG_MPHY_RX_GEN_SEL_INDEX(lane) (PA_MAXDATALANES + (lane))

#define UIC_ARG_MIB_SEL(attr, sel)  ((((attr) & 0xFFFF) << 16) |\
                     ((sel) & 0xFFFF))
#define UIC_ARG_MIB(attr)       UIC_ARG_MIB_SEL(attr, 0)
#define UIC_ARG_ATTR_TYPE(t)        (((t) & 0xFF) << 16)
#define UIC_GET_ATTR_ID(v)      (((v) >> 16) & 0xFFFF)


enum UfsIoCommands {
    UFS_CMD_WRITE              = 0x01,
    UFS_CMD_READ               = 0x02,
};

enum LnvmAdminCommands {
    LNVM_ADM_CMD_IDENTITY          = 0xe2,
    LNVM_ADM_CMD_GET_L2P_TBL       = 0xea,
    LNVM_ADM_CMD_GET_BB_TBL        = 0xf2,
    LNVM_ADM_CMD_SET_BB_TBL        = 0xf1,
};


enum LnvmDmCommands {
    LNVM_CMD_HYBRID_WRITE      = 0x81,
    LNVM_CMD_HYBRID_READ       = 0x02,
    LNVM_CMD_PHYS_WRITE        = 0x91,
    LNVM_CMD_PHYS_READ         = 0x92,
    LNVM_CMD_ERASE_ASYNC        = 0x90,
};

enum LnvmMetaState {
    LNVM_SEC_UNKNOWN = 0x0,
    LNVM_SEC_WRITTEN = 0xAC,
    LNVM_SEC_ERASED = 0xDC,
};
enum UfsStatusCodes {
    UFS_SUCCESS                = 0x0000,
	UFS_INVALID_OPCODE         = 0x0001,
	UFS_INVALID_FIELD          = 0x0002,
	UFS_INVALID_LUNID          = 0x000b,
    UFS_NO_COMPLETE            = 0xffff,
};

/* UIC Config result code / Generic error code */
enum {
    UIC_CMD_RESULT_SUCCESS          = 0x00,
    UIC_CMD_RESULT_INVALID_ATTR     = 0x01,
    UIC_CMD_RESULT_FAILURE          = 0x01,
    UIC_CMD_RESULT_INVALID_ATTR_VALUE   = 0x02,
    UIC_CMD_RESULT_READ_ONLY_ATTR       = 0x03,
    UIC_CMD_RESULT_WRITE_ONLY_ATTR      = 0x04,
    UIC_CMD_RESULT_BAD_INDEX        = 0x05,
    UIC_CMD_RESULT_LOCKED_ATTR      = 0x06,
    UIC_CMD_RESULT_BAD_TEST_FEATURE_INDEX   = 0x07,
    UIC_CMD_RESULT_PEER_COMM_FAILURE    = 0x08,
    UIC_CMD_RESULT_BUSY         = 0x09,
    UIC_CMD_RESULT_DME_FAILURE      = 0x0A,
};

#define MASK_UIC_COMMAND_RESULT         0xFF
#define UFS_ID_NS_FLBAS_INDEX(flbas)       ((flbas & 0xf))

/* Interrupt disable masks */
enum {
    /* Interrupt disable mask for UFSHCI v1.0 */
    INTERRUPT_MASK_ALL_VER_10   = 0x30FFF,
    INTERRUPT_MASK_RW_VER_10    = 0x30000,

    /* Interrupt disable mask for UFSHCI v1.1 */
    INTERRUPT_MASK_ALL_VER_11   = 0x31FFF,

    /* Interrupt disable mask for UFSHCI v2.1 */
    INTERRUPT_MASK_ALL_VER_21   = 0x71FFF,
};


/*
 * Request Descriptor Definitions
 */

/* Transfer request command type */
enum {
    UTP_CMD_TYPE_SCSI       = 0x0,
    UTP_CMD_TYPE_UFS        = 0x1,
    UTP_CMD_TYPE_DEV_MANAGE     = 0x2,
};

typedef struct request_desc_header{
    uint32_t dword_0;
    uint32_t dword_1;
    uint32_t dword_2;
    uint32_t dword_3;
}request_desc_header;

typedef struct SegEntry{
    uint32_t base_addr;
    uint32_t upper_addr;
    uint32_t reserved;
    uint32_t size;
}SegEntry;

/* UFS Command Descriptor structure */
typedef struct UtpTransferCmdDesc{
    uint8_t command_upiu[ALIGNED_UPIU_SIZE];
    uint8_t response_upiu[ALIGNED_UPIU_SIZE];
    struct SegEntry prd_table[128];
}UtpTransferCmdDesc;

/* UFS Tramsfer Request Descriptor structure */
typedef struct UtpTransferReqDesc {

    /* DW 0-3 */
    struct request_desc_header header;

    /* DW 4-5*/
    uint32_t  command_desc_base_addr_lo;
    uint32_t  command_desc_base_addr_hi;

    /* DW 6 */
    uint16_t  response_upiu_length;
    uint16_t  response_upiu_offset;

    /* DW 7 */
    uint16_t  prd_table_length;
    uint16_t  prd_table_offset;
}UtpTransferReqDesc;

  /* UTP Task Request Descriptor */
typedef struct UtpTaskReqDesc {

    /* DW 0-3 */
    struct request_desc_header header;

    /* DW 4-11 */
    uint32_t task_req_upiu[TASK_REQ_UPIU_SIZE_DWORDS];

    /* DW 12-19 */
    uint32_t task_rsp_upiu[TASK_RSP_UPIU_SIZE_DWORDS];
}UtpTaskReqDesc;

typedef struct UfsLBAF {
    uint16_t    ms;
    uint8_t     ds;
    uint8_t     rp;
} UfsLBAF;

typedef struct NUfsIdNs {
    uint64_t    nsze;
    uint64_t    ncap;
    uint64_t    nuse;
    uint8_t     nsfeat;
    uint8_t     nlbaf;
    uint8_t     flbas;
    uint8_t     mc;
    uint8_t     dpc;
    uint8_t     dps;
    uint8_t     res30[98];
    UfsLBAF    lbaf[16];
    uint8_t     res192[192];
    uint8_t     vs[3712];
} UfsIdNs;

typedef struct UfsLun {
    struct UfsCtrl *ctrl;
	UfsIdNs        id_ns;
    UfsRangeType    lba_range[64];
    unsigned long   *util;
    unsigned long   *uncorrectable;
    uint32_t        id;
    uint64_t        ns_blks;
    uint64_t        start_block;
    uint64_t        meta_start_offset;
    uint64_t        tbl_dsk_start_offset;
    uint32_t        tbl_entries;
    uint64_t        *tbl;
    uint8_t         *bbtbl;
} UfsLun;


typedef struct LnvmIdAddrFormat {	//Ch--Lun--Pln--Blk--Pg--Sect			aran-lq
    uint8_t  ch_offset;
    uint8_t  ch_len;
    uint8_t  lun_offset;
    uint8_t  lun_len;
    uint8_t  pln_offset;
    uint8_t  pln_len;
    uint8_t  blk_offset;
    uint8_t  blk_len;
    uint8_t  pg_offset;
    uint8_t  pg_len;
    uint8_t  sect_offset;
    uint8_t  sect_len;
    uint8_t  res[4];
} QEMU_PACKED LnvmIdAddrFormat;


typedef struct LnvmAddrF {				//Ch--Lun--Pln--Blk--Pg--Sect		aran-lq
	uint64_t	ch_mask;
	uint64_t	lun_mask;
	uint64_t	pln_mask;
	uint64_t	blk_mask;
	uint64_t	pg_mask;
	uint64_t	sec_mask;
	uint8_t	   ch_offset;
	uint8_t	   lun_offset;
	uint8_t	   pln_offset;
	uint8_t	   blk_offset;
	uint8_t	   pg_offset;
	uint8_t	   sec_offset;
} LnvmAddrF;

typedef struct LnvmIdGroup {
    uint8_t    mtype;
    uint8_t    fmtype;
    uint16_t   res16;
    uint8_t    num_ch;
    uint8_t    num_lun;
    uint8_t    num_pln;
    uint8_t    rsvd1;
    uint16_t   num_blk;
    uint16_t   num_pg;
    uint16_t   fpg_sz;
    uint16_t   csecs;
    uint16_t   sos;
    uint16_t   rsvd2;
    uint32_t   trdt;			//typical page read time(in ns)		aran-lq
    uint32_t   trdm;
    uint32_t   tprt;
    uint32_t   tprm;
    uint32_t   tbet;
    uint32_t   tbem;
    uint32_t   mpos;			// multi-plane operations supports			aran-lq
    uint32_t   mccap;
    uint16_t   cpar;
    uint8_t    res[906];
} QEMU_PACKED LnvmIdGroup;	

typedef struct LnvmIdCtrl {					//lightnvm controller identification info, global parameters 	aran-lq
    uint8_t       ver_id;
    uint8_t       vmnt;	                    //Vendor Opcode     aran-lq
    uint8_t       cgrps;
    uint8_t       res;
    uint32_t      cap;
    uint32_t      dom;						//device operation mode: Hybrid mode & ECC mode		aran-lq
    struct LnvmIdAddrFormat ppaf;
    uint8_t       resv[228];
    LnvmIdGroup   groups[4];
} QEMU_PACKED LnvmIdCtrl;


typedef struct LnvmParams {
    /* configurable device characteristics */
    uint16_t    pgs_per_blk;
    uint16_t    sec_size;
    uint8_t     sec_per_pg;
    uint8_t     max_sec_per_rq;
    /* configurable parameters for LnvmIdGroup */
    uint8_t     mtype;		//media type		aran-lq
    uint8_t     fmtype;		//flash media type	aran-lq
    uint8_t     num_ch;
    uint8_t     num_pln;
    uint8_t     num_lun;
    uint16_t    sos;			//sector OOB size  		aran-lq
    /* calculated values */
    uint32_t    sec_per_pl;
    uint32_t    sec_per_blk;
    uint32_t    sec_per_lun;
    uint32_t    total_secs;
    /* Calculated unit values for ordering */
    uint32_t    pl_units;
    uint32_t    pg_units;
    uint32_t    blk_units;
    uint32_t    lun_units;
    uint32_t    total_units;
} QEMU_PACKED LnvmParams;

typedef struct UfsRequest {
    struct TransReqList       *rl;
	struct TaskManageList     *ml;
    struct UfsLun		      *lun;
	uint64_t                slba;
	uint16_t                nlb;
	uint16_t                status;
	uint8_t                 cmd_opcode;
	uint16_t                is_write;
    BlockAIOCB              *aiocb;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;			//qemu io vector		?	aran-lq
    QTAILQ_ENTRY(UfsRequest)entry;
} UfsRequest;

typedef struct TransReqList {				
	UtpTaskReqDesc *utmrdl_base_addr;  
	uint8_t     nutrs;  				//num of transfer request	aran-lq
	uint8_t     cmd_opcode;
	struct UfsCtrl *ctrl;
    uint64_t    dma_addr;
    uint64_t    completed;
	uint32_t    size;
	uint32_t    head;
    uint32_t    tail;
    QEMUTimer   *timer;
    UfsRequest *io_req;
    QTAILQ_HEAD(trans_req_list, UfsRequest) req_list;
    QTAILQ_ENTRY(UfsRequest) entry;

}TransReqList;

typedef struct TaskManageList {		
	UtpTaskReqDesc *utmrdl_base_addr;  
	uint8_t     nutmrs;  				//num of task management request	aran-lq
	struct UfsCtrl *ctrl;
    uint64_t    dma_addr;
    uint64_t    completed;
	uint32_t    size;
	uint32_t    head;
    uint32_t    tail;
    QEMUTimer   *timer;
    UfsRequest *io_req;
    QTAILQ_HEAD(tm_req_list, UfsRequest) req_list;
    QTAILQ_ENTRY(UfsRequest) entry;

}TaskManageList;


#define TYPE_UFS "ufshcd"
#define UFS(obj) \
        OBJECT_CHECK(UfsCtrl, (obj), TYPE_UFS)

typedef struct LnvmCtrl {				
	LnvmParams     params;
    LnvmIdCtrl     id_ctrl;
    LnvmAddrF      ppaf;
    uint8_t        read_l2p_tbl;
    uint8_t        bbt_gen_freq;
    uint8_t        bbt_auto_gen;
    uint8_t        meta_auto_gen;
    uint8_t        debug;
    uint8_t        strict;
    char           *bbt_fname;
    char           *meta_fname;
    FILE           *bbt_fp;
    uint32_t       err_write;
    uint32_t       n_err_write;
    uint32_t       err_write_cnt;
    FILE           *metadata;
    uint8_t        int_meta_size; 
}LnvmCtrl;

			
 /* UFS device host controller  */ 
typedef struct UfsCtrl {				//nvme controller 	aran-lq
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    UfsBar       bar;					//register		aran-lq
    BlockConf    conf;

    time_t      start_time;
    uint16_t    temperature;
    uint16_t    page_size;
    uint16_t    page_bits;
    uint32_t    reg_size;
	uint16_t    trle_size;				//transfer request list entry size				aran-lq
	uint16_t    tmle_size;				//task management request list entry size		aran-lq
	uint64_t    ns_size;
    uint32_t    num_luns;			    //num of luns		aran-lq
    uint64_t    lun_size;
    uint8_t     nutrs;                  //Number of UTP Transfer Request Slots  aran-lq
    uint8_t     nutmrs;                 //Number of UTP Task Management Request Slots  aran-lq
    uint32_t    ver;					//version	aran-lq
    uint8_t     meta;
    uint16_t    vid; 					//vendor ID 	aran-lq
    uint16_t    did;					//device ID		aran-lq

    char        *serial;
    QEMUTimer   *aer_timer;
    uint8_t     aer_mask;
    UfsLun      *luns;
	TransReqList *trl;					//Transfer request List		aran-lq
	TaskManageList *tml;				//Task management list		aran-lq
    UtpTaskReqDesc *utmrdl_base_addr;        //指向task list的基地址   aran-lq
    UtpTransferReqDesc *utrdl_base_addr;     //指向transfer request 的基地址   aran-lq
    UtpTransferCmdDesc *ucdl_base_addr;		 //pointer of utp command desriptor		aran-lq

    LnvmCtrl     lnvm_ctrl;			//lnvm controller		aran-lq
} UfsCtrl;




//static void ufs_init_pci(UfsCtrl *n)__attribute__ ((unused));
//static void ufs_init_ctrl(UfsCtrl *n)__attribute__ ((unused));
static int lnvm_init(UfsCtrl *n)__attribute__ ((unused));
static int lnvm_init_meta(LnvmCtrl *n)__attribute__ ((unused));
static void lnvm_init_id_ctrl(LnvmCtrl *n)__attribute__ ((unused));
static void ufs_init_lun(UfsCtrl *n)__attribute__ ((unused));
static int ufs_check_constraints(UfsCtrl *n)__attribute__ ((unused));
static void ufs_write_bar(UfsCtrl *n, hwaddr offset, uint64_t data, unsigned size)__attribute__ ((unused));



#endif
