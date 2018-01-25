/*
 * UFS HOST Controller
 *
 * Copyright (c) 2017, CQU Lab 611
 *
 * Written by Aran-lq <liqi9281@gmail.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include <block/block_int.h>
#include <block/qapi.h>
#include <exec/memory.h>
#include <hw/block/block.h>
#include <hw/hw.h>
#include <hw/pci/pci.h>
#include <qapi/visitor.h>
#include <qemu/bitops.h>
#include <qemu/bitmap.h>
#include <sysemu/sysemu.h>
#include <sysemu/block-backend.h>
#include <qemu/main-loop.h>

#include "ufs.h"
#include "trace.h"



#define LNVM_MAX_GRPS_PR_IDENT (20)
#define LNVM_FEAT_EXT_START 64
#define LNVM_FEAT_EXT_END 127
#define LNVM_PBA_UNMAPPED UINT64_MAX
#define LNVM_LBA_UNMAPPED UINT64_MAX



static void ufs_addr_read(UfsCtrl *n, hwaddr addr, void *buf, int size)
{
        pci_dma_read(&n->parent_obj, addr, buf, size);
    
}

/* update irq line */
/* The function to update interrupt , aran-lq*/
static inline void ufs_update_irq(UfsCtrl *n)
{
    int level = 0;

    if ((n->bar.is & UFSINTR_MASK) & n->bar.ie) {
        level = 1;
    }

    qemu_set_irq(n->irq, level);
}


static void ufs_update_trl_slot(const TransReqList *trl)
{
	
}

static void ufs_update_tml_slot(const TaskManageList *tml)
{
	
}

static uint8_t ufs_tml_empty(TaskManageList *tml)
{
    return tml->head == tml->tail;
}


static uint8_t ufs_trl_empty(TransReqList *trl)
{
    return trl->head == trl->tail;
}

static uint32_t lnvm_tbl_size(UfsLun *ns)
{
	return ns->tbl_entries * sizeof(*(ns->tbl));
}



static uint8_t lnvm_dev(UfsCtrl *n)
{
    return (n->lnvm_ctrl.id_ctrl.ver_id != 0);
}

static int lnvm_bbt_load(UfsLun *ns, uint32_t nr_blocks,
						 uint32_t offset, uint8_t *blks)
{
    struct LnvmCtrl *ln = &ns->ctrl->lnvm_ctrl;
    FILE *fp;
    size_t ret;

    if (!ln->bbt_fname)
        return 0;

    fp = fopen(ln->bbt_fname, "r");
    if (!fp) {
        memcpy(blks, ns->bbtbl, nr_blocks);
        return 0;
    }

    if (fseek(fp, offset, SEEK_SET)) {
        printf("Could not read bb file\n");
        return -1;
    }

    ret = fread(blks, 1, nr_blocks, fp);
    if (ret != nr_blocks) {
        printf("Could not read bb file\n");
        return -1;
    }

    fclose(fp);
    return 0;
}

static int lnvm_read_tbls(UfsCtrl *n)
{
    uint32_t i;

    for (i = 0; i < n->num_luns; i++) {
        UfsLun *ns = &n->luns[i];
        uint32_t tbl_size = lnvm_tbl_size(ns);
        if (blk_pread(n->conf.blk, ns->tbl_dsk_start_offset,
					  ns->tbl, tbl_size) != tbl_size) {
            return -1;
        }
    }

    return 0;
}
static void ufs_rw_cb(void *opaque, int ret)
{
	
}

static uint16_t ufs_map_prp(QEMUSGList *qsg, QEMUIOVector *iov,
                             uint64_t prp1, uint64_t prp2, uint32_t len, UfsCtrl *n)
{
	return 0;

}

static uint16_t lnvm_rw(UfsCtrl *n, UfsLun *ns, CmdUPIU *cmd,
						UfsRequest *req)
{
	return 0;
}
	
static uint16_t ufs_rw(UfsCtrl *n, UfsLun *ns, CmdUPIU *cmd,
						UfsRequest *req)
{
	printf("ufs read or write subprocess\n");
	UfsRwCmd *rw = (UfsRwCmd *)cmd;
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    uint64_t slba;
    const uint8_t lba_index = UFS_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = nlb << data_shift;
    uint64_t aio_slba;
	
    slba = le64_to_cpu(rw->slba);
    req->is_write = rw->opcode == UFS_CMD_WRITE;
    aio_slba = ns->start_block + (slba << (data_shift - BDRV_SECTOR_BITS));
	
    if (ufs_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {

        return UFS_INVALID_FIELD;
    }
	
    req->slba = slba;
    req->status = UFS_SUCCESS;
    req->nlb = nlb;
    req->lun = ns;
	
    dma_acct_start(n->conf.blk, &req->acct, &req->qsg, req->is_write ?
				BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);
  
   req->aiocb = req->is_write ?
				dma_blk_write(n->conf.blk, &req->qsg, aio_slba, ufs_rw_cb, req) :
				dma_blk_read(n->conf.blk, &req->qsg, aio_slba, ufs_rw_cb, req);

    return UFS_NO_COMPLETE;
    return 0;
}


static uint16_t ufs_tm_cmd(UfsCtrl *n, CmdUPIU *cmd, UfsRequest *req)
{
	return 0;
}

static uint16_t ufs_io_cmd(UfsCtrl *n, CmdUPIU *cmd, UfsRequest *req)
{
	printf("This is a io command.\n");
    UfsLun *luns;
    uint32_t lunid = le32_to_cpu(cmd->lunid);
	
    if (lunid == 0 || lunid > n->num_luns) {			//LUN ID num limit		aran-lq
        return UFS_INVALID_LUNID;
    }
	
    luns = &n->luns[lunid - 1];
    switch (cmd->opcode) {
		case LNVM_CMD_HYBRID_WRITE:
		case LNVM_CMD_PHYS_READ:
		case LNVM_CMD_PHYS_WRITE:
			return lnvm_rw(n, luns, cmd, req);
		case UFS_CMD_READ:
		case UFS_CMD_WRITE:
			return ufs_rw(n, luns, cmd, req);
		default:
			return UFS_INVALID_OPCODE;
    }
}

/**
 * ufs_get_db_slot - Get Door bell register 
 * @hba: per-adapter instance
 * @tag: pointer to variable with current set slot.
 */
static bool ufs_get_db_slot(struct UfsCtrl *n, int *tag_out)
{	
	int i = 0;
	bool ret = false;
	unsigned long tmp;
	int shift_tag;
	
	if (!tag_out)
		goto out;

	tmp = n->bar.utrldbr;
	do{
		tag_out[i] = find_last_bit(&tmp, n->nutrs);
		//printf("tag[%d]: %d\n",i,tag_out[i]);
		shift_tag = 1 << tag_out[i];
		tmp &= ~shift_tag;
		i++;
	} while (tag_out[i] < n->nutrs);
	ret = true;
out:
	return ret;
}


static void ufs_tm_req_completion(TaskManageList *trl, UfsRequest *req)
{
	
}

static void ufs_enqueue_req_completion(TransReqList *trl, UfsRequest *req)
{
	
}

static void ufs_process_tml(void *opaque)
{
	printf("ufs process task management request list\n");
    TaskManageList *tml = opaque;
    UfsCtrl *n = tml->ctrl;
    uint16_t status;
    hwaddr addr;
    CmdUPIU cmd;
    UfsRequest *req;
	
    while (!(ufs_tml_empty(tml) || QTAILQ_EMPTY(&tml->req_list))) {				//while loop		aran-lq
	
        addr = tml->dma_addr + tml->head * n->tmle_size;
        ufs_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
	
        req = QTAILQ_FIRST(&tml->req_list);
        QTAILQ_REMOVE(&tml->req_list, req, entry);
        req->aiocb = NULL;
        req->cmd_opcode = cmd.opcode;
		status=ufs_tm_cmd(n, &cmd, req);
        if (status != UFS_NO_COMPLETE) {
            req->status = status;
            ufs_tm_req_completion(tml, req);
        }
		ufs_update_tml_slot(tml);													//clear the slot		aran-lq
	}
	
    if (!ufs_tml_empty(tml)) {
        timer_mod(tml->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }

}

static void ufs_process_trl(void *opaque)
{
	printf("ufs process transfer request list\n");
    TransReqList *trl = opaque;
    UfsCtrl *n = trl->ctrl;
    uint16_t status;
    hwaddr addr;
    CmdUPIU cmd;
    UfsRequest *req;
	
    while (!(ufs_trl_empty(trl) || QTAILQ_EMPTY(&trl->req_list))) {				//while loop		aran-lq

        addr = trl->dma_addr + trl->head * n->trle_size;
        ufs_addr_read(n, addr, (void *)&cmd, sizeof(cmd));

        req = QTAILQ_FIRST(&trl->req_list);
        QTAILQ_REMOVE(&trl->req_list, req, entry);
        req->aiocb = NULL;
        req->cmd_opcode = cmd.opcode;
		status=ufs_io_cmd(n, &cmd, req);
        if (status != UFS_NO_COMPLETE) {
            req->status = status;
            ufs_enqueue_req_completion(trl, req);
        }
    ufs_update_trl_slot(trl);													//clear the slot		aran-lq
	}

    if (!ufs_trl_empty(trl)) {
        timer_mod(trl->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }

}

static uint16_t ufs_init_trl(TransReqList *trl, UfsCtrl *n, uint64_t dma_addr)
{
	printf("ufs init transfer request list.\n");
    int i;	
    trl->head = trl->tail = 0;
    trl->dma_addr = dma_addr;
	//malloc memory for trl		aran-lq
    trl->io_req = g_malloc0(trl->size * sizeof(*trl->io_req));
    QTAILQ_INIT(&trl->req_list);
	//insert in the queue		aran-lq
    for (i = 0; i < trl->size; i++) {
        trl->io_req[i].rl = trl;
        QTAILQ_INSERT_TAIL(&(trl->req_list), &trl->io_req[i], entry);
    }
	
    trl->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ufs_process_trl, trl);

	return 0;
}

static uint16_t ufs_init_tml(TaskManageList *tml, UfsCtrl *n, uint64_t dma_addr)
{
	printf("ufs init task management list.\n");
	int i;	
    tml->head = tml->tail = 0;
    tml->dma_addr = dma_addr;
	//malloc memory for trl		aran-lq
    tml->io_req = g_malloc0(tml->size * sizeof(*tml->io_req));
    QTAILQ_INIT(&tml->req_list);
	//insert in the queue		aran-lq
    for (i = 0; i < tml->size; i++) {
        tml->io_req[i].ml = tml;
        QTAILQ_INSERT_TAIL(&(tml->req_list), &tml->io_req[i], entry);
    }
	
    tml->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ufs_process_tml, tml);

	return 0;
}
static void uic_cmd_complete(UfsCtrl *n)
{
	printf("UIC command complete procedure. \n");
	n->bar.ucmdarg2 &= 0xffffff00;
	n->bar.is |= UFS_UCCS_COMPL;
	//device present
	n->bar.hcs|= UFS_DP_READY;
	n->bar.hcs|= UFS_UTRLRDY_READY;
	n->bar.hcs|= UFS_UTMRLRDY_READY;                              
	ufs_update_irq(n);
	
	//qemu_set_irq(n->irq, 1);
	//qemu_set_irq(n->irq, 0);
}

static void ufs_clear_ctrl(UfsCtrl *n)
   {

   }                                 
   

static int ufs_start_ctrl(UfsCtrl *n)
   {
	   printf("ufs start controller.\n");
	   n->nutrs = 0x20;//32
	   n->nutmrs = 0x8;//8

	   
	   /*  some para init		aran-lq
	   n->page_bits = page_bits;
	   n->page_size = 1 << n->page_bits;
	   n->max_prp_ents = n->page_size / sizeof(uint64_t);
	   */
	   ufs_init_trl(n->trl, n, n->bar.utrlba);
	   ufs_init_tml(n->tml, n, n->bar.utmrlba);
	   return 0;
   }
 
static void ufs_db_process(UfsCtrl *n)
{
	int tag[32] = {0};
	if(!ufs_get_db_slot(n, tag))
		printf("Error when getting db slot.\n");
	for(int i =0; i < 32; i++)
		printf("tag_out[%d] = %d\n",i, tag[i]);
	//UtpTransferReqDesc *utrd = n->bar.utrlba;
}

static void ufs_write_bar(UfsCtrl *n, hwaddr offset, uint64_t data, unsigned size)
{
	printf("ufs write bar.\n");
    switch (offset) {
		case 0x20:
			printf("Interrupt Status write, the value was %x.\n",n->bar.is);
			//IS is a RWC register.
			n->bar.is &= ~(data & 0xffffffff);
			ufs_update_irq(n);//Everytime host write IS with '1' will clear coresponding bit.
			printf("Interrupt Status write, now value is %x.\n",n->bar.is);
		case 0x24:
			printf("Interrupt Enable write, value was %x.\n",n->bar.ie);
			n->bar.ie = data & 0xffffffff;
			printf("Interrupt Enable write, now value is %x.\n",n->bar.ie);
		case 0x34:
			printf("HCE write .\n");
			if ((UFS_HCE_EN(data) && !UFS_HCE_EN(n->bar.hce))){
				printf("HCE was %x.\n",n->bar.hce);
				n->bar.hce = data & 0xffffffff;
				printf("HCE is %x.\n",n->bar.hce);
				//UIC command ready.
				n->bar.hcs = UFS_UICCMD_READY;
				
				if(!ufs_start_ctrl(n)){

					printf("HCS command  ready. \n");
				}else {
					printf("HCS command not ready. \n");
				}
			}
		//UTRIACR register
		case 0x4C:
			printf("UTP Transfer Request Interrupt Aggregation Control Register.\n");
			n->bar.utriacr = data & 0xffffffff;
			printf("UTRIACR register value is %x.\n",n->bar.utriacr);
		case 0x50:
			printf("UTP Transfer Request List Base Address.\n");
			n->bar.utrlba = data & 0xffffffff;
		case 0x54:
			printf("UTP Transfer Request List Base Address Upper 32-Bits.\n");
			n->bar.utrlbau = data & 0xffffffff;
		//Door Bell
		case 0x58:
			printf("UTP Transfer Request List Door Bell Register.\n");
			//UTRLDBR is a RWS register.
			n->bar.utrldbr |= (data & 0xffffffff); 
			printf("Door bell number is %x\n", n->bar.utrldbr);
			ufs_db_process(n);
		case 0x60:
			printf("UTP Task Management Request List Run Stop register.\n");
			n->bar.utrlrsr = data & 0xffffffff;
		case 0x70:
			printf("UTP Task Management Request List Base Address.\n");
			n->bar.utmrlba = data & 0xffffffff;
		case 0x74:
			printf("UTP Task Management Request List Base Address Upper 32-Bits.\n");
			n->bar.utmrlbau = data & 0xffffffff;
		case 0x80:
			printf("UTP Task Management Request List Base Address Upper 32-Bits.\n");
			n->bar.utmrlrsr = data & 0xffffffff;
		case 0x90:
			printf("UIC command writes. Value was %x.\n", n->bar.uiccmd);
			n->bar.uiccmd = data & 0xffffffff;
			if(n->bar.uiccmd == UIC_CMD_DME_LINK_STARTUP)//DME_LINK_STARTUP command	aran-lq
				uic_cmd_complete(n);
			printf("UIC command writes. Now value is %x.\n", n->bar.uiccmd);
		case 0x94:
			printf("UIC arg1 writes. Value was %x.\n", n->bar.ucmdarg1);
			n->bar.ucmdarg1 = data & 0xffffffff;
			printf("UIC arg1 writes. Now value is %x.\n", n->bar.ucmdarg1);
		case 0x98:
			printf("UIC arg2 writes. Value was %x.\n", n->bar.ucmdarg2);
			n->bar.ucmdarg2 = data & 0xffffffff;
			printf("UIC arg2 writes. Now value is %x.\n", n->bar.ucmdarg3);
		case 0x9c:
			printf("UIC arg1 writes. Value was %x.\n", n->bar.ucmdarg3);
			n->bar.ucmdarg3 = data & 0xffffffff;
			printf("UIC arg3 writes. Now value is %x.\n", n->bar.ucmdarg3);
			
		
		default:
				break;
	}
}

static uint64_t ufs_mmio_read(void *opaque, hwaddr addr, unsigned size)
{	   
	 printf("ufs mmio read.\n");
     UfsCtrl *n = (UfsCtrl *)opaque;
     uint8_t *ptr = (uint8_t *)&n->bar;
     uint32_t val = 0;

     if (addr < sizeof(n->bar)) {
          memcpy(&val, ptr + addr, size);
      }
 
      trace_nvme_mmio_read(addr, size, val);

	return val;
}


static void ufs_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
	  printf("ufs mmio write.\n");
	  UfsCtrl *n = (UfsCtrl *)opaque;
	  if (addr < sizeof(n->bar)) {
		  ufs_write_bar(n, addr, data, size);
	  } else 
		 printf("Out of bar's address.\n");
	  
      
      trace_nvme_mmio_write(addr, size, data);
}



static const MemoryRegionOps ufs_mmio_ops = {
    .read = ufs_mmio_read,
    .write = ufs_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static int ufs_check_constraints(UfsCtrl *n)
{
	
    return 0;
}

static void ufs_init_lun(UfsCtrl *n)
{
	
 }

static void lnvm_init_id_ctrl(LnvmCtrl *ln)
{ 
	LnvmIdCtrl *ln_id = &ln->id_ctrl;
    ln_id->ver_id = 1;
    ln_id->vmnt = 0;
    ln_id->cgrps = 1;
    ln_id->cap = cpu_to_le32(0x3);
		
    ln_id->ppaf.sect_offset = 0;
    ln_id->ppaf.sect_len = qemu_fls(cpu_to_le16(ln->params.sec_per_pg) - 1);
    ln_id->ppaf.pln_offset = ln_id->ppaf.sect_offset + ln_id->ppaf.sect_len;
    ln_id->ppaf.pln_len = qemu_fls(cpu_to_le16(ln->params.num_pln) - 1);
    ln_id->ppaf.pg_offset = ln_id->ppaf.pln_offset + ln_id->ppaf.pln_len;
    ln_id->ppaf.pg_len = qemu_fls(cpu_to_le16(ln->params.pgs_per_blk) - 1);
    ln_id->ppaf.blk_offset = ln_id->ppaf.pg_offset + ln_id->ppaf.pg_len;
    ln_id->ppaf.blk_len = qemu_fls(cpu_to_le16(ln->id_ctrl.groups[0].num_blk) - 1);
    ln_id->ppaf.lun_offset = ln_id->ppaf.blk_offset + ln_id->ppaf.blk_len;
    ln_id->ppaf.lun_len = qemu_fls(cpu_to_le16(ln->params.num_lun) - 1);
    ln_id->ppaf.ch_offset = ln_id->ppaf.lun_offset + ln_id->ppaf.lun_len;
    ln_id->ppaf.ch_len = qemu_fls(cpu_to_le16(ln->params.num_ch) - 1);
 }

static int lnvm_init_meta(LnvmCtrl *ln)
{
	char *state = NULL;
    struct stat buf;
    size_t meta_tbytes, res;
	
    ln->int_meta_size = 4;      // Internal meta (state: ERASED / WRITTEN)
	
    //
    // Internal meta are the first "ln->int_meta_size" bytes
    // Then comes the tgt_oob_len with is the following ln->param.sos bytes
    //
	
    meta_tbytes = (ln->int_meta_size + ln->params.sos) * \
                  ln->params.total_secs;
	
    if (!ln->meta_fname) {      // Default meta file
        ln->meta_auto_gen = 1;
        ln->meta_fname = malloc(10);
        if (!ln->meta_fname)
            return -ENOMEM;
        strncpy(ln->meta_fname, "meta.qemu\0", 10);
    } else {
        ln->meta_auto_gen = 0;
    }
	
    ln->metadata = fopen(ln->meta_fname, "w+"); // Open the metadata file
    if (!ln->metadata) {
        error_report("ufs: lnvm_init_meta: fopen(%s)\n", ln->meta_fname);
        return -EEXIST;
    }
	
    if (fstat(fileno(ln->metadata), &buf)) {
        error_report("ufs: lnvm_init_meta: fstat(%s)\n", ln->meta_fname);
        return -1;
    }
	
    if (buf.st_size == meta_tbytes)             // All good
        return 0;
	
    //
    // Create meta-data file when it is empty or invalid
    //
    if (ftruncate(fileno(ln->metadata), 0)) {
        error_report("ufs: lnvm_init_meta: ftrunca(%s)\n", ln->meta_fname);
        return -1;
    }
	
    state = malloc(meta_tbytes);
    if (!state) {
        error_report("ufs: lnvm_init_meta: malloc f(%s)\n", ln->meta_fname);
        return -ENOMEM;
    }
	
    memset(state, LNVM_SEC_UNKNOWN, meta_tbytes);
	
    res = fwrite(state, 1, meta_tbytes, ln->metadata);
	
    free(state);
	
    if (res != meta_tbytes) {
        error_report("ufs: lnvm_init_meta: fwrite(%s), res(%lu)\n",
                     ln->meta_fname, res);
        return -1;
    }
	
    rewind(ln->metadata);
	
    return 0;
}

static int lnvm_init(UfsCtrl *n)				//lnvm   controller 初始化函数				aran-lq
{
    LnvmCtrl *ln;
    LnvmIdGroup *c;
    UfsLun *ns;
    unsigned int i;
    uint64_t chnl_blks;
    uint32_t nr_total_blocks;
    int ret = 0;
	
    ln = &n->lnvm_ctrl;
	
    if (ln->params.mtype != 0)
        error_report("ufs: Only NAND Flash Memory supported at the moment\n");
    if (ln->params.fmtype != 0)
        error_report("ufs: Only SLC Flash is supported at the moment\n");
    if (ln->params.num_ch != 1)
        error_report("ufs: Only 1 channel is supported at the moment\n");
    if ((ln->params.num_pln > 4) || (ln->params.num_pln == 3))
        error_report("ufs: Only single, dual and quad plane modes supported \n");
	
    for (i = 0; i < n->num_luns; i++) {
        ns = &n->luns[i];
        chnl_blks = ns->ns_blks / (ln->params.sec_per_pg * ln->params.pgs_per_blk);
	
        c = &ln->id_ctrl.groups[0];
        c->mtype = ln->params.mtype;
        c->fmtype = ln->params.fmtype;
        c->num_ch = ln->params.num_ch;
        c->num_lun = ln->params.num_lun;
        c->num_pln = ln->params.num_pln;
	
        c->num_blk = cpu_to_le16(chnl_blks) / (c->num_lun * c->num_pln);
        c->num_pg = cpu_to_le16(ln->params.pgs_per_blk);
        c->csecs = cpu_to_le16(ln->params.sec_size);
        c->fpg_sz = cpu_to_le16(ln->params.sec_size * ln->params.sec_per_pg);
        c->sos = cpu_to_le16(ln->params.sos);
	
        c->trdt = cpu_to_le32(70000);
        c->trdm = cpu_to_le32(100000);
        c->tprt = cpu_to_le32(1900000);
        c->tprm = cpu_to_le32(3500000);
        c->tbet = cpu_to_le32(3000000);
        c->tbem = cpu_to_le32(3000000);
	
        switch(c->num_pln) {
            case 1:
                c->mpos = cpu_to_le32(0x10101); /* single plane */
                break;
            case 2:
                c->mpos = cpu_to_le32(0x20202); /* dual plane */
                break;
            case 4:
                c->mpos = cpu_to_le32(0x40404); /* quad plane */
                break;
            default:
                error_report("ufs: Invalid plane mode\n");
                return -EINVAL;
        }
	
        nr_total_blocks = c->num_blk * c->num_pln * c->num_lun;
        c->cpar = cpu_to_le16(0);
        c->mccap = 1;
        ns->bbtbl = qemu_blockalign(blk_bs(n->conf.blk), nr_total_blocks);
        memset(ns->bbtbl, 0, nr_total_blocks);
	
        ret = (lnvm_bbt_load(ns, nr_total_blocks, 0, ns->bbtbl));
        if (ret)
            return ret;
	
        /* We devide the address space linearly to be able to fit into the 4KB
         * sectors that the ufs driver divides the backend file. We do the
         * division in LUNS - BLOCKS - PLANES - PAGES - SECTORS.
         *
         * For example a quad plane configuration is layed out as:
         * -----------------------------------------------------------
         * |                        QUAD PLANE                       |
         * -------------- -------------- -------------- --------------
         * |   LUN 00   | |   LUN 01   | |   LUN 02   | |   LUN 03   |
         * -------------- -------------- -------------- --------------
         * |   BLOCKS            |          ...          |   BLOCKS  |
         * ----------------------
         * |   PLANES   |              ...               |   PLANES  |
         * -------------                                 -------------
         * | PAGES |                 ...                 |   PAGES   |
         * -----------------------------------------------------------
         * |                        ALL SECTORS                      |
         * -----------------------------------------------------------
         */
	
        /* calculated values */
        ln->params.sec_per_pl = ln->params.sec_per_pg * c->num_pln;
        ln->params.sec_per_blk = ln->params.sec_per_pl * ln->params.pgs_per_blk;
        ln->params.sec_per_lun = ln->params.sec_per_blk * c->num_blk;
        ln->params.total_secs = ln->params.sec_per_lun * c->num_lun;
	
        /* Calculated unit values for ordering */
        ln->params.pl_units = ln->params.sec_per_pg;
        ln->params.pg_units = ln->params.pl_units * c->num_pln;
        ln->params.blk_units = ln->params.pg_units * ln->params.pgs_per_blk;
        ln->params.lun_units = ln->params.blk_units * c->num_blk;
        ln->params.total_units = ln->params.lun_units * c->num_lun;
	
        /* previous address format 
        ln->ppaf.blk_offset = 0;
        ln->ppaf.pg_offset = ln->id_ctrl.ppaf.blk_len;
        ln->ppaf.sec_offset = ln->ppaf.pg_offset + ln->id_ctrl.ppaf.pg_len;
        ln->ppaf.pln_offset = ln->ppaf.sec_offset + ln->id_ctrl.ppaf.sect_len;
        ln->ppaf.lun_offset = ln->ppaf.pln_offset + ln->id_ctrl.ppaf.pln_len;
        ln->ppaf.ch_offset = ln->ppaf.lun_offset + ln->id_ctrl.ppaf.lun_len;
        */
	
		lnvm_init_id_ctrl(ln);
        /* Address format: CH | LUN | BLK | PG | PL | SEC */
        ln->ppaf.sec_offset = ln->id_ctrl.ppaf.sect_offset;
        ln->ppaf.pln_offset = ln->id_ctrl.ppaf.pln_offset;
        ln->ppaf.pg_offset = ln->id_ctrl.ppaf.pg_offset;
        ln->ppaf.blk_offset = ln->id_ctrl.ppaf.blk_offset;
        ln->ppaf.lun_offset = ln->id_ctrl.ppaf.lun_offset;
        ln->ppaf.ch_offset = ln->id_ctrl.ppaf.ch_offset;
	
        /* Address component selection MASK */
        ln->ppaf.sec_mask = ((1 << ln->id_ctrl.ppaf.sect_len) - 1) <<
							ln->ppaf.sec_offset;
        ln->ppaf.pln_mask = ((1 << ln->id_ctrl.ppaf.pln_len) - 1) <<
							ln->ppaf.pln_offset;
        ln->ppaf.pg_mask = ((1 << ln->id_ctrl.ppaf.pg_len) - 1) <<
						   ln->ppaf.pg_offset;
        ln->ppaf.blk_mask = ((1 << ln->id_ctrl.ppaf.blk_len) - 1) <<
							ln->ppaf.blk_offset;
        ln->ppaf.lun_mask = ((1 << ln->id_ctrl.ppaf.lun_len) -1) <<
							ln->ppaf.lun_offset;
        ln->ppaf.ch_mask = ((1 << ln->id_ctrl.ppaf.ch_len) - 1) <<
						   ln->ppaf.ch_offset;
    }
	
    if (!ln->bbt_fname) {       // Default bbt file
        ln->bbt_auto_gen = 1;
        ln->bbt_fname = malloc(13);
        if (!ln->bbt_fname)
            return -ENOMEM;
        strncpy(ln->bbt_fname, "bbtable.qemu\0", 13);
    } else {
        ln->bbt_auto_gen = 0;
    }
	
    ret = lnvm_init_meta(ln);   // Initialize metadata file
    if (ret) {
        error_report("ufs: lnvm_init_meta: failed\n");
        return ret;
    }
	
    ret = (n->lnvm_ctrl.read_l2p_tbl) ? lnvm_read_tbls(n) : 0;
    if (ret) {
        error_report("ufs: cannot read l2p table\n");
        return ret;
    }
	
    return 0;
}


static void ufs_init_ctrl(UfsCtrl *n)
{
	  n->bar.cap = 0;
	  UFS_CAP_SET_NUTRS(n->bar.cap, n->nutrs);
	  UFS_CAP_SET_NUTMRS(n->bar.cap, n->nutmrs);
	  UFS_CAP_SET_NORTT(n->bar.cap, 2);	//num(2) of outstanding RTT request support
	  UFS_CAP_SET_64AS(n->bar.cap, 1); 

	  /* HCI register init aran-lq */
	  n->bar.vs = 		0x00000210;
	  n->bar.is = 		0x00000000;
	  n->bar.ie = 		0x00000000;
	  n->bar.hcs = 		0x00000000;
	  n->bar.hce = 		0x00000000;
	  n->bar.utrlba = 	0x00000000;
	  n->bar.utrlbau =	0x00000000;
	  n->bar.utrldbr = 	0x00000000;
	  n->bar.utrlclr = 	0x00000000;
	  n->bar.utrlrsr = 	0x00000000;
	  n->bar.utmrlba = 	0x00000000;
	  n->bar.utmrlbau = 0x00000000;
	  n->bar.utmrldbr = 0x00000000;
	  n->bar.utmrlclr = 0x00000000;
	  n->bar.utmrlrsr = 0x00000000;
	  
}

static void ufs_init_pci(UfsCtrl *n)
{   
    uint8_t *pci_conf = n->parent_obj.config;
    pci_conf[PCI_INTERRUPT_PIN] = 4;//PIN_D		aran-lq
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, 0x0000);	
    memory_region_init_io(&n->iomem, OBJECT(n), &ufs_mmio_ops, n, "ufshcd",
        n->reg_size);
    pci_register_bar(&n->parent_obj, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &n->iomem);
	//interrupt allocate	aran-lq
	n->irq = pci_allocate_irq(&n->parent_obj);

   
}

static int ufs_init(PCIDevice *pci_dev)				//传入的是一个pci_dev的设备指针				aran-lq
{	  
      UfsCtrl *n = UFS(pci_dev);
	  int64_t bs_size;

	  blkconf_serial(&n->conf, &n->serial);
      if (ufs_check_constraints(n)) {
	      return -1;
      }

      bs_size = blk_getlength(n->conf.blk);
      if (bs_size < 0) {
          return -1;
      }

      n->start_time = time(NULL);
      n->reg_size = 1 << qemu_fls(0x103);			//all Register sizes		aran-lq
	  n->ns_size = bs_size / (uint64_t)n->num_luns;

      n->trl = g_malloc0(sizeof(*n->trl));			//malloca transfer request list		aran-lq
      n->tml = g_malloc0(sizeof(*n->tml));
      n->luns = g_malloc0(sizeof(*n->luns));

	   ufs_init_pci(n);
	   ufs_init_ctrl(n);					
       ufs_init_lun(n);
       if (lnvm_dev(n))
          return lnvm_init(n);				//添加的代码 			aran-lq
    return 0;
}

static void lnvm_exit(UfsCtrl *n)
{
    LnvmCtrl *ln = &n->lnvm_ctrl;

   if (ln->bbt_auto_gen)
        free(ln->bbt_fname);
   if (ln->meta_auto_gen)
       free(ln->meta_fname);
	fclose(n->lnvm_ctrl.bbt_fp);
	fclose(n->lnvm_ctrl.metadata);
	n->lnvm_ctrl.bbt_fp = NULL;
	n->lnvm_ctrl.metadata = NULL;
}

static void ufs_exit(PCIDevice *pci_dev)			
{
      UfsCtrl *n = UFS(pci_dev);

      ufs_clear_ctrl(n);
	  g_free(n->luns);
      g_free(n->trl);
      g_free(n->tml);
	  
	  //free IRQ  aran-lq
	  if (n->irq) {
		  g_free(n->irq);
		  n->irq = NULL;
	  }
	  
      if (lnvm_dev(n)) {
          lnvm_exit(n);			
    }
}

static Property ufs_props[] = {
      DEFINE_BLOCK_PROPERTIES(UfsCtrl, conf),
	  DEFINE_PROP_STRING("serial", UfsCtrl, serial),
	  DEFINE_PROP_UINT32("luns", UfsCtrl, num_luns, 1),	//name, state, field, defval	aran-lq
	  DEFINE_PROP_UINT16("vid", UfsCtrl, vid, 0x144d),
	  DEFINE_PROP_UINT16("did", UfsCtrl, did, 0xc00c),
	  DEFINE_PROP_UINT8("nutrs", UfsCtrl, nutrs, 31),
	  DEFINE_PROP_UINT8("nutmrs", UfsCtrl, nutmrs, 7),
	  DEFINE_PROP_UINT8("lver", UfsCtrl, lnvm_ctrl.id_ctrl.ver_id, 0),
	  DEFINE_PROP_UINT32("ll2pmode", UfsCtrl, lnvm_ctrl.id_ctrl.dom, 0),
	  DEFINE_PROP_UINT16("lsec_size", UfsCtrl, lnvm_ctrl.params.sec_size, 4096),
	  DEFINE_PROP_UINT8("lsecs_per_pg", UfsCtrl, lnvm_ctrl.params.sec_per_pg, 1),
	  DEFINE_PROP_UINT16("lpgs_per_blk", UfsCtrl, lnvm_ctrl.params.pgs_per_blk, 256),
	  DEFINE_PROP_UINT8("lmax_sec_per_rq", UfsCtrl, lnvm_ctrl.params.max_sec_per_rq, 64),
	  DEFINE_PROP_UINT8("lmtype", UfsCtrl, lnvm_ctrl.params.mtype, 0),
	  DEFINE_PROP_UINT8("lfmtype", UfsCtrl, lnvm_ctrl.params.fmtype, 0),
	  DEFINE_PROP_UINT8("lnum_ch", UfsCtrl, lnvm_ctrl.params.num_ch, 1),
	  DEFINE_PROP_UINT8("lnum_lun", UfsCtrl, lnvm_ctrl.params.num_lun, 1),
	  DEFINE_PROP_UINT8("lnum_pln", UfsCtrl, lnvm_ctrl.params.num_pln, 1),
	  DEFINE_PROP_UINT8("lreadl2ptbl", UfsCtrl, lnvm_ctrl.read_l2p_tbl, 1),
	  DEFINE_PROP_STRING("lbbtable", UfsCtrl, lnvm_ctrl.bbt_fname),
	  DEFINE_PROP_STRING("lmetadata", UfsCtrl, lnvm_ctrl.meta_fname),
	  DEFINE_PROP_UINT16("lmetasize", UfsCtrl, lnvm_ctrl.params.sos, 16),
	  DEFINE_PROP_UINT8("lbbfrequency", UfsCtrl, lnvm_ctrl.bbt_gen_freq, 0),
	  DEFINE_PROP_UINT32("lb_err_write", UfsCtrl, lnvm_ctrl.err_write, 0),
	  DEFINE_PROP_UINT32("ln_err_write", UfsCtrl, lnvm_ctrl.n_err_write, 0),
	  DEFINE_PROP_UINT8("ldebug", UfsCtrl, lnvm_ctrl.debug, 0),
	  DEFINE_PROP_UINT8("lstrict", UfsCtrl, lnvm_ctrl.strict, 0),
 
      DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription ufs_vmstate = {
    .name = "ufshcd",
    .unmigratable = 1,                          
};

static void ufs_class_init(ObjectClass *oc, void *data)
{	
    DeviceClass *dc = DEVICE_CLASS(oc);			//将信息分别给到device_class和pci_device_class				aran-lq
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = ufs_init;						//包括了lnvm_init				aran-lq
    pc->exit = ufs_exit;
    pc->class_id = 0x0000;     //PCI Storage Scsi                  aran-lq
    pc->vendor_id = 0x144d;


    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Universal Flash Storage";
    dc->props = ufs_props;
    dc->vmsd = &ufs_vmstate;                    //vmstate   aran-lq
}

static void ufs_get_bootindex(Object *obj, Visitor *v, void *opaque,
                                  const char *name, Error **errp)
{
    UfsCtrl *s = UFS(obj);

    visit_type_int32(v, &s->conf.bootindex, name, errp);
}

static void ufs_set_bootindex(Object *obj, Visitor *v, void *opaque,
                                  const char *name, Error **errp)
{
    UfsCtrl *s = UFS(obj);
    int32_t boot_index;
    Error *local_err = NULL;

    visit_type_int32(v, &boot_index, name, &local_err);
    if (local_err) {
        goto out;
    }
    /* check whether bootindex is present in fw_boot_order list  */
    check_boot_index(boot_index, &local_err);
    if (local_err) {
        goto out;
    }
    /* change bootindex to a new one */
    s->conf.bootindex = boot_index;

out:
    if (local_err) {
        error_propagate(errp, local_err);
    }
}

static void ufs_instance_init(Object *obj)
{
    object_property_add(obj, "bootindex", "int32",
                        ufs_get_bootindex,
                        ufs_set_bootindex, NULL, NULL, NULL);
    object_property_set_int(obj, -1, "bootindex", NULL);
}

static const TypeInfo ufs_info = {
    .name          = "ufshcd",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(UfsCtrl),
    .class_init    = ufs_class_init,
    .instance_init = ufs_instance_init,
};

static void ufs_register_types(void)
{
    type_register_static(&ufs_info);
}

type_init(ufs_register_types)
