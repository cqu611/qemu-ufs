
#include <block/block_int.h>
#include <block/qapi.h>
#include <exec/memory.h>
#include <hw/block/block.h>
#include <hw/hw.h>
//#include <hw/pci/msix.h>
//#include <hw/pci/msi.h>
#include <hw/pci/pci.h>
#include <qapi/visitor.h>
#include <qemu/bitops.h>
#include <qemu/bitmap.h>
#include <sysemu/sysemu.h>
#include <sysemu/block-backend.h>
#include <qemu/main-loop.h>

#include "ufs.h"
#include "trace.h"

#define NVME_MAX_QS PCI_MSIX_FLAGS_QSIZE
#define NVME_MAX_QUEUE_ENTRIES  0xffff
#define NVME_MAX_STRIDE         12
#define NVME_MAX_NUM_NAMESPACES 256
#define NVME_MAX_QUEUE_ES       0xf
#define NVME_MIN_CQUEUE_ES      0x4
#define NVME_MIN_SQUEUE_ES      0x6
#define NVME_SPARE_THRESHOLD    20
#define NVME_TEMPERATURE        0x143
#define NVME_OP_ABORTED         0xff

#define LNVM_MAX_GRPS_PR_IDENT (20)
#define LNVM_FEAT_EXT_START 64
#define LNVM_FEAT_EXT_END 127
#define LNVM_PBA_UNMAPPED UINT64_MAX
#define LNVM_LBA_UNMAPPED UINT64_MAX

//         status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
//             nvme_admin_cmd(n, &cmd, req);		//通过sqid的值，判断是io命令还是管理命令					aran-lq
//         if (status != NVME_NO_COMPLETE) {
//             req->status = status;
//             nvme_enqueue_req_completion(cq, req);
//         }
//     }
//     nvme_update_sq_eventidx(sq);
//     nvme_update_sq_tail(sq);
// 
//     sq->completed += processed;
//     if (!nvme_sq_empty(sq)) {
//         timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
//     }
// }
// 
// static void nvme_clear_ctrl(NvmeCtrl *n)
// {
//     NvmeAsyncEvent *event;
//     int i;
// 
//     for (i = 0; i < n->num_queues; i++) {
//         if (n->sq[i] != NULL) {
//             nvme_free_sq(n->sq[i], n);
//         }
//     }
//     for (i = 0; i < n->num_queues; i++) {
//         if (n->cq[i] != NULL) {
//             nvme_free_cq(n->cq[i], n);
//         }
//     }
//     if (n->aer_timer) {
//         timer_del(n->aer_timer);
//         timer_free(n->aer_timer);
//         n->aer_timer = NULL;
//     }
//     while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
//         QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
//         g_free(event);
//     }
// 
//     blk_flush(n->conf.blk);
//     if (lnvm_hybrid_dev(n))
//         lnvm_flush_tbls(n);
//     n->bar.cc = 0;
//     n->features.temp_thresh = 0x14d;
//     n->temp_warn_issued = 0;
//     n->outstanding_aers = 0;
// }
// 
// static int nvme_start_ctrl(NvmeCtrl *n)
// {
//     uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
//     uint32_t page_size = 1 << page_bits;
// 
//     if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
//             n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
//             NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
//             NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
//             NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
//             NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
//             NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
//             NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
//             !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
//             !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
//         return -1;
//     }
// 
//     n->page_bits = page_bits;
//     n->page_size = 1 << n->page_bits;
//     n->max_prp_ents = n->page_size / sizeof(uint64_t);
//     n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
//     n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);
// 
//     nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
//             NVME_AQA_ACQS(n->bar.aqa) + 1, 1, 1);
//     nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
//             NVME_AQA_ASQS(n->bar.aqa) + 1, NVME_Q_PRIO_HIGH, 1);
// 
//     n->aer_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_aer_process_cb, n);
//     QSIMPLEQ_INIT(&n->aer_queue);
//     return 0;
// }

static void ufs_write_bar(UfsCtrl *n, hwaddr offset, uint64_t data, unsigned size)
{
 //   switch (offset) {
 //   case 0xc:
 //       n->bar.intms |= data & 0xffffffff;
 //       n->bar.intmc = n->bar.intms;
 //       break;
 //   case 0x10:
 //       n->bar.intms &= ~(data & 0xffffffff);
 //       n->bar.intmc = n->bar.intms;
 //       break;
 //   case 0x14:		//第14个寄存器 	 CC controller configuration		aran-lq
 //       if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
 //           n->bar.cc = data;
 //           if (nvme_start_ctrl(n)) {
 //               n->bar.csts = NVME_CSTS_FAILED;
 //           } else {
 //               n->bar.csts = NVME_CSTS_READY;
 //           }
 //       } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
 //           nvme_clear_ctrl(n);
 //           n->bar.csts &= ~NVME_CSTS_READY;
 //       }
 //       if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
 //               nvme_clear_ctrl(n);
 //               n->bar.cc = data;
 //               n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
 //       } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
 //               n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
 //               n->bar.cc = data;
 //       }
 //       break;
 //   case 0x24:
 //       n->bar.aqa = data & 0xffffffff;
 //       break;
 //   case 0x28:
 //       n->bar.asq = data;
 //       break;
 //   case 0x2c:
 //       n->bar.asq |= data << 32;
 //       break;
 //   case 0x30:
 //       n->bar.acq = data;
 //       break;
 //   case 0x34:
 //       n->bar.acq |= data << 32;
 //       break;
 //   default:
 //       break;
 //   }
}

static uint64_t ufs_mmio_read(void *opaque, hwaddr addr, unsigned size)
{	   
	 printf("ufs mmio read.\n");
//    NvmeCtrl *n = (NvmeCtrl *)opaque;
//    uint8_t *ptr = (uint8_t *)&n->bar;
//    uint64_t val = 0;
//
//    if (addr < sizeof(n->bar)) {
//        memcpy(&val, ptr + addr, size);
//    }
//
//    trace_nvme_mmio_read(addr, size, val);
//
//    return val;
    return 0;
}

// static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
// {
//     uint32_t qid;
//     uint16_t new_val = val & 0xffff;
//     NvmeSQueue *sq;
// 
//     if (addr & ((1 << (2 + n->db_stride)) - 1)) {
//         nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
//             NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
//         return;
//     }
// 
//     if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
//         NvmeCQueue *cq;
//         bool start_sqs;
// 
//         qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
//             (3 + n->db_stride);
//         if (nvme_check_cqid(n, qid)) {
//             nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
//                 NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
//             return;
//         }
// 
//         cq = n->cq[qid];
//         if (new_val >= cq->size) {
//             nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
//                 NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
//             return;
//         }
// 
//         start_sqs = nvme_cq_full(cq) ? true : false;
// 
//         /* When the mapped pointer memory area is setup, we don't rely on
//          * the MMIO written values to update the head pointer. */
//         if (!cq->db_addr) {
//             cq->head = new_val;
//         }
//         if (start_sqs) {
//             NvmeSQueue *sq;
//             QTAILQ_FOREACH(sq, &cq->sq_list, entry) {
//                 if (!timer_pending(sq->timer)) {
//                     timer_mod(sq->timer, qemu_clock_get_ns(
//                                             QEMU_CLOCK_VIRTUAL) + 500);
//                 }
//             }
//             nvme_post_cqes(cq);
//         } else if (cq->tail != cq->head) {
//             nvme_isr_notify(cq);
//         }
//     } else {
//         qid = (addr - 0x1000) >> (3 + n->db_stride);
//         if (nvme_check_sqid(n, qid)) {
//             nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
//                 NVME_AER_INFO_ERR_INVALID_SQ, NVME_LOG_ERROR_INFO);
//             return;
//         }
//         sq = n->sq[qid];
//         if (new_val >= sq->size) {
//             nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
//                 NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
//             return;
//         }
// 
//         /* When the mapped pointer memory area is setup, we don't rely on
//          * the MMIO written values to update the tail pointer. */
//         if (!sq->db_addr) {
//             sq->tail = new_val;
//         }
//         if (!timer_pending(sq->timer)) {
//             timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
//         }
//     }
//}

static void ufs_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
	  printf("ufs mmio write.\n");
 //   NvmeCtrl *n = (NvmeCtrl *)opaque;
 //   if (addr < sizeof(n->bar)) {
 //       nvme_write_bar(n, addr, data, size);
 //   } else if (addr >= 0x1000) {
 //       nvme_process_db(n, addr, data);
 //   }

 //   trace_nvme_mmio_write(addr, size, data);
}

// static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data,
//     unsigned size)
// {
//     NvmeCtrl *n = (NvmeCtrl *)opaque;
//     memcpy(&n->cmbuf[addr], &data, size);
// 
//     trace_nvme_cmb_write(addr, size, data);			//没有函数定义 				aran-lq
// }
// 
// static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
// {
//     uint64_t val;
//     NvmeCtrl *n = (NvmeCtrl *)opaque;
// 
//     memcpy(&val, &n->cmbuf[addr], size);
//     trace_nvme_cmb_read(addr, size, val);			//没有函数定义			aran-lq
//     return val;
// }

//static const MemoryRegionOps nvme_cmb_ops = {			//controller memory buffer		参看最前面  aran-lq
//    .read = nvme_cmb_read,
//    .write = nvme_cmb_write,
//    .endianness = DEVICE_LITTLE_ENDIAN,
//    .impl = {
//        .min_access_size = 2,
//        .max_access_size = 8,
//    },
//};

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
		printf("ufs check constraints\n");
 //   if ((!(n->conf.blk)) || !(n->serial) ||
 //       (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) ||
 //       (n->num_queues < 1 || n->num_queues > NVME_MAX_QS) ||
 //       (n->db_stride > NVME_MAX_STRIDE) ||
 //       (n->max_q_ents < 1) ||
 //       (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
 //           n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) ||
 //       (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) ||
 //       (n->nlbaf > 16) ||
 //       (n->lba_index >= n->nlbaf) ||
 //       (n->meta && !n->mc) ||
 //       (n->extended && !(NVME_ID_NS_MC_EXTENDED(n->mc))) ||
 //       (!n->extended && n->meta && !(NVME_ID_NS_MC_SEPARATE(n->mc))) ||
 //       (n->dps && n->meta < 8) ||
 //       (n->dps && ((n->dps & DPS_FIRST_EIGHT) &&
 //           !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc))) ||
 //       (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
 //           !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) ||
 //       (n->dps & DPS_TYPE_MASK && !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
 //           (1 << ((n->dps & DPS_TYPE_MASK) - 1)))) ||
 //       (n->mpsmax > 0xf || n->mpsmax > n->mpsmin) ||
 //       (n->oacs & ~(NVME_OACS_FORMAT)) ||
 //       (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
 //           NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS))) {
 //       return -1;
 //   }
    return 0;
}

static void ufs_init_lun(UfsCtrl *n)
{
	printf("ufs init lun\n");
 }

static void lnvm_init_id_ctrl(LnvmCtrl *ln)
{
 }

static int lnvm_init_meta(LnvmCtrl *ln)
{
     return 0;
}

static int lnvm_init(UfsCtrl *n)				//lnvm   controller 初始化函数				aran-lq
{
     return 0;
}


static void ufs_init_ctrl(UfsCtrl *n)
{
	  printf("ufs init ctrl \n");
      //int i;
//      UfsIdCtrl *id = &n->id_ctrl;
//	  uint8_t *pci_conf = n->parent_obj.config;

//	  id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
//      id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
 //     strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU Ufs Ctrl", ' ');
 //     strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
//      strpadcpy((char *)id->sn, sizeof(id->sn), n->serial, ' ');
 //   id->rab = 6;
 //   id->ieee[0] = 0x00;
 //   id->ieee[1] = 0x02;
 //   id->ieee[2] = 0xb3;
 //   id->cmic = 0;
 //   id->mdts = n->mdts;
 //   id->oacs = cpu_to_le16(n->oacs);
 //   id->acl = n->acl;
 //   id->aerl = n->aerl;
 //   id->frmw = 7 << 1 | 1;
 //   id->lpa = 0 << 0;
 //   id->elpe = n->elpe;
 //   id->npss = 0;
 //   id->sqes = (n->max_sqes << 4) | 0x6;
 //   id->cqes = (n->max_cqes << 4) | 0x4;
 //   id->nn = cpu_to_le32(n->num_namespaces);
 //   id->oncs = cpu_to_le16(n->oncs);
 //   id->fuses = cpu_to_le16(0);
 //   id->fna = 0;
 //   id->vwc = n->vwc;
 //   id->awun = cpu_to_le16(0);
 //   id->awupf = cpu_to_le16(0);
 //   id->psd[0].mp = cpu_to_le16(0x9c4);
 //   id->psd[0].enlat = cpu_to_le32(0x10);
 //   id->psd[0].exlat = cpu_to_le32(0x4);

 //   n->features.arbitration     = 0x1f0f0706;
 //   n->features.power_mgmt      = 0;
 //   n->features.temp_thresh     = 0x14d;
 //   n->features.err_rec         = 0;
 //   n->features.volatile_wc     = n->vwc;
 //   n->features.num_queues      = (n->num_queues - 1) |
 //                                ((n->num_queues - 1) << 16);
 //   n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
 //   n->features.write_atomicity = 0;
 //   n->features.async_config    = 0x0;
 //   n->features.sw_prog_marker  = 0;

 //   for (i = 0; i < n->num_queues; i++) {
 //       n->features.int_vector_config[i] = i | (n->intc << 16);
 //   }
 //   /* 寄存器设置        aran-lq */
	  n->bar.cap = 0x1707101f;
	  n->bar.vs = 0x00000210;
	  n->bar.is = 0x00000000;
	  n->bar.ie = 0x00000000;
	  n->bar.hcs = 0x0000000f;
	  n->bar.hce = 0x00000001;
	  n->bar.utrlba = 0x80000000;
	  n->bar.utrlbau = 0xb0000000;
	  n->bar.utrldbr = 0x00000000;
	  n->bar.utrlclr = 0x00000000;
	  n->bar.utrlrsr = 0x00000000;
	  n->bar.utmrlba = 0xe0000000;
	  n->bar.utmrlbau = 0xf8000000;
	  n->bar.utmrldbr = 0x00000000;
	  n->bar.utmrlclr = 0x00000000;
	  n->bar.utmrlrsr = 0x00000000;
	  
	  printf("ufs init ctrl over \n");

	  
	
   
 
}

static void ufs_init_pci(UfsCtrl *n)
{   
	printf("ufs init pci\n");
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, 0x0000);						//change to Zero			aran-lq
  //  pcie_endpoint_cap_init(&n->parent_obj, 0x80);								// NO pcie 					aran-lq

    memory_region_init_io(&n->iomem, OBJECT(n), &ufs_mmio_ops, n, "ufshcd",		//nvme_mmio_ops  函数注册吗？				aran-lq
        n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
	
	printf("ufs init pci over\n");
   
}

static int ufs_init(PCIDevice *pci_dev)				//传入的是一个pci_dev的设备指针				aran-lq
{	  
	  printf("ufs_init\n");
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
 //     n->reg_size = 1 << qemu_fls(0x1004 + 2 * (n->num_queues + 1) * 4);
 //   n->ns_size = bs_size / (uint64_t)n->num_namespaces;

 //   n->sq = g_malloc0(sizeof(*n->sq)*n->num_queues);
 //   n->cq = g_malloc0(sizeof(*n->cq)*n->num_queues);
 //   n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
 //   n->elpes = g_malloc0((n->elpe + 1) * sizeof(*n->elpes));
 //   n->aer_reqs = g_malloc0((n->aerl + 1) * sizeof(*n->aer_reqs));
 //   n->features.int_vector_config = g_malloc0(n->num_queues *
 //       sizeof(*n->features.int_vector_config));

	   ufs_init_pci(n);
	   ufs_init_ctrl(n);						//nvmeIdCtrl 的初始化，主要是Controller register CAP的置位和设置等等		  aran-lq
 //   ufs_init_lun(n);
 //   if (lnvm_dev(n))
 //       return lnvm_init(n);				//添加的代码 			aran-lq
	   printf("ufs_init over\n");
    return 0;
}

static void lnvm_exit(UfsCtrl *n)
{
 //   LnvmCtrl *ln = &n->lnvm_ctrl;

 //   if (ln->bbt_auto_gen)
 //       free(ln->bbt_fname);
 //   if (ln->meta_auto_gen)
 //       free(ln->meta_fname);
 //   fclose(n->lnvm_ctrl.bbt_fp);
 //   fclose(n->lnvm_ctrl.metadata);
 //   n->lnvm_ctrl.bbt_fp = NULL;
 //   n->lnvm_ctrl.metadata = NULL;
}

static void ufs_exit(PCIDevice *pci_dev)
{
	  printf("ufs exit\n");
 //   UfsCtrl *n = UFS(pci_dev);

 //   ufs_clear_ctrl(n);
 //   g_free(n->namespaces);
 //   g_free(n->features.int_vector_config);
 //   g_free(n->aer_reqs);
 //   g_free(n->elpes);
 //   g_free(n->cq);
 //   g_free(n->sq);
 //   msix_uninit_exclusive_bar(pci_dev);         //msix 中断       aran-lq
 //   memory_region_unref(&n->iomem);
 //   if (n->cmbsz) {
 //       memory_region_unref(&n->ctrl_mem);
 //   }

 //   if (lnvm_dev(n)) {
 //       lnvm_exit(n);					//执行lnvm的离开
 //   }
}

static Property ufs_props[] = {
      DEFINE_BLOCK_PROPERTIES(UfsCtrl, conf),
 //   DEFINE_PROP_STRING("serial", NvmeCtrl, serial),
 //   DEFINE_PROP_UINT32("namespaces", NvmeCtrl, num_namespaces, 1),	//name, state, field, defval	aran-lq
 //   DEFINE_PROP_UINT32("queues", NvmeCtrl, num_queues, 64),
 //   DEFINE_PROP_UINT32("entries", NvmeCtrl, max_q_ents, 0x7ff),
 //   DEFINE_PROP_UINT8("max_cqes", NvmeCtrl, max_cqes, 0x4),
 //   DEFINE_PROP_UINT8("max_sqes", NvmeCtrl, max_sqes, 0x6),
 //   DEFINE_PROP_UINT8("stride", NvmeCtrl, db_stride, 0),
 //   DEFINE_PROP_UINT8("aerl", NvmeCtrl, aerl, 3),
 //   DEFINE_PROP_UINT8("acl", NvmeCtrl, acl, 3),
 //   DEFINE_PROP_UINT8("elpe", NvmeCtrl, elpe, 3),
 //   DEFINE_PROP_UINT8("mdts", NvmeCtrl, mdts, 10),
 //   DEFINE_PROP_UINT8("cqr", NvmeCtrl, cqr, 1),
 //   DEFINE_PROP_UINT8("vwc", NvmeCtrl, vwc, 0),
 //   DEFINE_PROP_UINT8("intc", NvmeCtrl, intc, 0),
 //   DEFINE_PROP_UINT8("intc_thresh", NvmeCtrl, intc_thresh, 0),
 //   DEFINE_PROP_UINT8("intc_time", NvmeCtrl, intc_time, 0),
 //   DEFINE_PROP_UINT8("mpsmin", NvmeCtrl, mpsmin, 0),
 //   DEFINE_PROP_UINT8("mpsmax", NvmeCtrl, mpsmax, 0),
 //   DEFINE_PROP_UINT8("nlbaf", NvmeCtrl, nlbaf, 5),
 //   DEFINE_PROP_UINT8("lba_index", NvmeCtrl, lba_index, 3),
 //   DEFINE_PROP_UINT8("extended", NvmeCtrl, extended, 0),
 //   DEFINE_PROP_UINT8("dpc", NvmeCtrl, dpc, 0),
 //   DEFINE_PROP_UINT8("dps", NvmeCtrl, dps, 0),
 //   DEFINE_PROP_UINT8("mc", NvmeCtrl, mc, 0),
 //   DEFINE_PROP_UINT8("meta", NvmeCtrl, meta, 0),
 //   DEFINE_PROP_UINT32("cmbsz", NvmeCtrl, cmbsz, 0),
 //   DEFINE_PROP_UINT32("cmbloc", NvmeCtrl, cmbloc, 0),
 //   DEFINE_PROP_UINT16("oacs", NvmeCtrl, oacs, NVME_OACS_FORMAT),
 //   DEFINE_PROP_UINT16("oncs", NvmeCtrl, oncs, NVME_ONCS_DSM),
      DEFINE_PROP_UINT16("vid", UfsCtrl, vid, 0x144d),
      DEFINE_PROP_UINT16("did", UfsCtrl, did, 0xc00c),
 //   DEFINE_PROP_UINT8("lver", NvmeCtrl, lnvm_ctrl.id_ctrl.ver_id, 0),
 //   DEFINE_PROP_UINT32("ll2pmode", NvmeCtrl, lnvm_ctrl.id_ctrl.dom, 1),
 //   DEFINE_PROP_UINT16("lsec_size", NvmeCtrl, lnvm_ctrl.params.sec_size, 4096),
 //   DEFINE_PROP_UINT8("lsecs_per_pg", NvmeCtrl, lnvm_ctrl.params.sec_per_pg, 1),
 //   DEFINE_PROP_UINT16("lpgs_per_blk", NvmeCtrl, lnvm_ctrl.params.pgs_per_blk, 256),
 //   DEFINE_PROP_UINT8("lmax_sec_per_rq", NvmeCtrl, lnvm_ctrl.params.max_sec_per_rq, 64),
 //   DEFINE_PROP_UINT8("lmtype", NvmeCtrl, lnvm_ctrl.params.mtype, 0),
 //   DEFINE_PROP_UINT8("lfmtype", NvmeCtrl, lnvm_ctrl.params.fmtype, 0),		//lnvm controller的参数信息设置 				aran-lq
 //   DEFINE_PROP_UINT8("lnum_ch", NvmeCtrl, lnvm_ctrl.params.num_ch, 1),
 //   DEFINE_PROP_UINT8("lnum_lun", NvmeCtrl, lnvm_ctrl.params.num_lun, 1),
 //   DEFINE_PROP_UINT8("lnum_pln", NvmeCtrl, lnvm_ctrl.params.num_pln, 1),
 //   DEFINE_PROP_UINT8("lreadl2ptbl", NvmeCtrl, lnvm_ctrl.read_l2p_tbl, 1),
 //   DEFINE_PROP_STRING("lbbtable", NvmeCtrl, lnvm_ctrl.bbt_fname),
 //   DEFINE_PROP_STRING("lmetadata", NvmeCtrl, lnvm_ctrl.meta_fname),
 //   DEFINE_PROP_UINT16("lmetasize", NvmeCtrl, lnvm_ctrl.params.sos, 16),
 //   DEFINE_PROP_UINT8("lbbfrequency", NvmeCtrl, lnvm_ctrl.bbt_gen_freq, 0),
 //   DEFINE_PROP_UINT32("lb_err_write", NvmeCtrl, lnvm_ctrl.err_write, 0),
 //   DEFINE_PROP_UINT32("ln_err_write", NvmeCtrl, lnvm_ctrl.n_err_write, 0),
 //   DEFINE_PROP_UINT8("ldebug", NvmeCtrl, lnvm_ctrl.debug, 0),
 //   DEFINE_PROP_UINT8("lstrict", NvmeCtrl, lnvm_ctrl.strict, 0),
      DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription ufs_vmstate = {
    .name = "ufshcd",
    .unmigratable = 1,                          
};

static void ufs_class_init(ObjectClass *oc, void *data)
{	
	printf("ufs class init\n");
    DeviceClass *dc = DEVICE_CLASS(oc);			//将信息分别给到device_class和pci_device_class				aran-lq
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = ufs_init;						//包括了lnvm_init				aran-lq
    pc->exit = ufs_exit;
    pc->class_id = 0x0000;     //PCI Storage Scsi                  aran-lq
    pc->vendor_id = 0x144d;
    //pc->is_express = 1;                       //NO PCIE						aran-lq

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Universal Flash Storage";
	printf("ufs property initialize\n");
    dc->props = ufs_props;
    dc->vmsd = &ufs_vmstate;                    //vmstate   aran-lq
	printf("ufs class init over\n");
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
	printf("ufs instance init\n");
    object_property_add(obj, "bootindex", "int32",
                        ufs_get_bootindex,
                        ufs_set_bootindex, NULL, NULL, NULL);
    object_property_set_int(obj, -1, "bootindex", NULL);
	printf("ufs instance over\n");
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
    printf("UFS register \n");
    type_register_static(&ufs_info);
}

type_init(ufs_register_types)
