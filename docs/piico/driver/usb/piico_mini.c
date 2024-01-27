#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif
#include <linux/completion.h>
#include <linux/usb.h>
#include <linux/wait.h>

#include "piico_mini.h"

/* Define these values to match your devices */
#define MINI_VENDOR_ID 0x9118
#define MINI_PRODUCT_ID 0x2104
#define MINI_PRODUCT_ID1 0x2206
#define MINI_PRODUCT_ID2 0x2208

int deviceNum = 0;
/* table of devices that work with this driver */
static struct usb_device_id mini_table[] = {
    {USB_DEVICE(MINI_VENDOR_ID, MINI_PRODUCT_ID)},
    {USB_DEVICE(MINI_VENDOR_ID, MINI_PRODUCT_ID1)},
    {USB_DEVICE(MINI_VENDOR_ID, MINI_PRODUCT_ID2)},
    {} /* Terminating entry */
};

void prt_buf(void *buf, size_t Len) {
  unsigned int i;
  char *In = (char *)buf;
  for (i = 0; i < Len; i++) {
    if (i && !(i % 16)) printk(KERN_INFO "\n");
    printk(KERN_INFO "%x", In[i]);
  }
}

MODULE_DEVICE_TABLE(usb, mini_table);

/* Get a minor range for your devices from the usb maintainer */
#define MINI_MINOR_BASE 192

/* Structure to hold all of our device specific stuff */
struct piico_mini {
  struct usb_device *udev;         /* the usb device for this device */
  struct usb_interface *interface; /* the interface for this device */
  struct semaphore limit_sem;    /* limiting the number of writes in progress */
  unsigned char *bulk_in_buffer; /* the buffer to receive data */
  size_t bulk_in_size;           /* the size of the receive buffer */
  unsigned char *bulk_out_buffer; /* the buffer to receive data */
  size_t bulk_out_size;           /* the size of the receive buffer */
  // struct urb *            bulk_in_urb;
  struct urb *bulk_out_urb;
  __u8 bulk_in_endpointAddr;  /* the address of the bulk in endpoint */
  __u8 bulk_out_endpointAddr; /* the address of the bulk out endpoint */
  struct kref kref;
  struct completion cpl;
  uint32_t MaxPacketSize;
  //	wait_queue_head_t	rw_waite;
};
#define to_mini_dev(d) container_of(d, struct piico_mini, kref)

static struct usb_driver mini_driver;

static void mini_delete(struct kref *kref) {
  struct piico_mini *dev = to_mini_dev(kref);

  usb_put_dev(dev->udev);
  kfree(dev->bulk_in_buffer);
  // usb_free_urb(dev->bulk_in_urb);
  kfree(dev->bulk_out_buffer);
  usb_free_urb(dev->bulk_out_urb);
  kfree(dev);
}

static int mini_open(struct inode *inode, struct file *file) {
  struct piico_mini *dev;
  struct usb_interface *interface;
  int subminor;
  int retval = 0;

  subminor = iminor(inode);

  interface = usb_find_interface(&mini_driver, subminor);
  if (!interface) {
    pr_err("%s - error, can't find device for minor %d", __FUNCTION__,
           subminor);
    retval = -ENODEV;
    goto exit;
  }

  dev = usb_get_intfdata(interface);
  if (!dev) {
    retval = -ENODEV;
    goto exit;
  }
  /*	if (down_interruptible(&dev->limit_sem)) {
                  retval = -ERESTARTSYS;
                  goto exit;
          }*/

  /* increment our usage count for the device */
  kref_get(&dev->kref);
  /* save our object in the file's private structure */
  file->private_data = dev;

exit:
  return retval;
}

static int mini_release(struct inode *inode, struct file *file) {
  struct piico_mini *dev;

  dev = (struct piico_mini *)file->private_data;
  if (dev == NULL) return -ENODEV;

  /* decrement the count on our device */
  kref_put(&dev->kref, mini_delete);
  //	up(&dev->limit_sem);
  return 0;
}

static void mini_write_read_callback(struct urb *urb) {
  //	printk(KERN_INFO"\n Start skel_write_read_callback");
  struct piico_mini *dev;

  dev = (struct piico_mini *)urb->context;

  /* sync/async unlink faults aren't errors */
  if (urb->status && !(urb->status == -ENOENT || urb->status == -ECONNRESET ||
                       urb->status == -ESHUTDOWN)) {
    pr_err("%s - nonzero write bulk status received: %d", __FUNCTION__,
           urb->status);
  }

  /* free up our allocated buffer */
  // usb_free_coherent(urb->dev, urb->transfer_buffer_length,
  //		urb->transfer_buffer, urb->transfer_dma);

  complete(&dev->cpl);
}

int mini_write_read(struct file *file, struct usr_parm *args) {
  struct piico_mini *dev;
  int bytes_read;
  int retval = 0;
  struct urb *urb = NULL;
  char *buf = NULL;
  uint32_t olen;
  uint32_t ilen;

  //	printk(KERN_INFO"\n Start skel_write_read");
  dev = (struct piico_mini *)file->private_data;

  /* verify that we actually have some data to write */
  if (args->ilen == 0) {
    retval = -1;
    goto exit;
  }

  /* limit the number of URBs in flight to stop a user from using up all RAM */
  if (down_interruptible(&dev->limit_sem)) {
    retval = -ERESTARTSYS;
    goto exit;
  }

  /* create a urb, and a buffer for it, and copy the data to the urb */
  // urb = usb_alloc_urb(0, GFP_KERNEL);
  // if (!urb) {
  //	retval = -ENOMEM;
  //	goto upsem;
  // }

  // buf = usb_alloc_coherent(dev->udev, args->ilen, GFP_KERNEL,
  // &urb->transfer_dma); if (!buf) { 	retval = -ENOMEM; 	goto freeurb;
  // }

  buf = dev->bulk_out_buffer;
  urb = dev->bulk_out_urb;

  if (copy_from_user(buf, args->idata, args->ilen)) {
    retval = -EFAULT;
    goto upsem;
  }

  //	prt_buf(buf,40);

  while (urb->hcpriv)
    ;

  ilen = args->ilen;

  if ((args->ilen % dev->MaxPacketSize) == 0) {
    // urb->transfer_flags |= URB_ZERO_PACKET;
    ilen += 4;
  }

  /* initialize the urb properly */
  usb_fill_bulk_urb(urb, dev->udev,
                    usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr), buf,
                    ilen, mini_write_read_callback, dev);
  // urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
  // if((args->ilen % dev->MaxPacketSize) == 0)
  //{
  //	urb->transfer_flags |= URB_ZERO_PACKET;   //It maybe can't work at old
  // kernel
  // }
  /* send the data out the bulk port */
  retval = usb_submit_urb(urb, GFP_KERNEL);

  if (retval) {
    pr_err("%s - failed submitting write urb, error %d", __FUNCTION__, retval);
    goto upsem;
  }

  /* release our reference to this urb, the USB core will eventually free it
   * entirely */
  // usb_free_urb(urb);

  if (args->olen == 0) {
    wait_for_completion(&dev->cpl);
    up(&dev->limit_sem);
    return 0;
  }

  olen = MAX_TRANSFER;
  /* do a blocking bulk read to get data from the device */
  retval = usb_bulk_msg(dev->udev,
                        usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
                        dev->bulk_in_buffer, olen, &bytes_read, 60000);

  /* if the read was successful, copy the data to userspace */
  if (!retval) {
    args->rlen = (bytes_read > args->olen) ? args->olen : bytes_read;
    if (copy_to_user(args->odata, dev->bulk_in_buffer, args->rlen))
      retval = -EFAULT;
    else
      retval = 0;
  }
  wait_for_completion(&dev->cpl);
  up(&dev->limit_sem);
  //	printk(KERN_INFO"\n End skel_write_read");
  return retval;

upsem:
  up(&dev->limit_sem);
exit:
  return retval;
}

long int mini_ioctl(struct file *filep, unsigned int cmd, unsigned long u_arg) {
  struct usr_parm k_arg;
  int retval = 0;

  switch (cmd) {
    case MINI_IOCX_RW:

      if (copy_from_user(&k_arg, (void __user *)u_arg, sizeof(k_arg)))
        return -EFAULT;
      if (k_arg.ilen > MAX_TRANSFER || k_arg.olen > MAX_TRANSFER)
        return -EFAULT;

      retval = mini_write_read(filep, &k_arg);
      if (copy_to_user((void __user *)u_arg, (void *)&k_arg, sizeof(k_arg)))
        retval = -EFAULT;
      return retval;
    default:
      return -ENOTTY; /* unknown command */
  }
  return 0;
}

static struct file_operations mini_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = mini_ioctl,
    .open = mini_open,
    .release = mini_release,
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
static struct usb_class_driver mini_class = {
    .name = "PiicoMiNi%d",
    .fops = &mini_fops,
    .minor_base = MINI_MINOR_BASE,
};

static int mini_probe(struct usb_interface *interface,
                      const struct usb_device_id *id) {
  struct piico_mini *dev = NULL;
  struct usb_host_interface *iface_desc;
  struct usb_endpoint_descriptor *endpoint;
  size_t buffer_size;
  int i;
  int retval = -ENOMEM;

  /* allocate memory for our device state and initialize it */
  dev = kzalloc(sizeof(*dev), GFP_KERNEL);
  if (dev == NULL) {
    pr_err("Out of memory");
    goto error;
  }
  kref_init(&dev->kref);
  sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
  init_completion(&dev->cpl);

  dev->udev = usb_get_dev(interface_to_usbdev(interface));
  dev->interface = interface;

  /* set up the endpoint information */
  /* use only the first bulk-in and bulk-out endpoints */
  iface_desc = interface->cur_altsetting;
  for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
    endpoint = &iface_desc->endpoint[i].desc;

    if (!dev->bulk_in_endpointAddr &&
        ((endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN) &&
        ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
         USB_ENDPOINT_XFER_BULK)) {
      /* we found a bulk in endpoint */
      buffer_size = BUFFER_SZ;
      dev->bulk_in_size = buffer_size;
      dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
      dev->bulk_in_buffer = kmalloc(buffer_size, GFP_KERNEL);
      if (!dev->bulk_in_buffer) {
        pr_err("Could not allocate bulk_in_buffer");
        goto error;
      }

      // dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
      // if (!dev->bulk_in_urb) {
      //	retval = -ENOMEM;
      //	goto error1;
      // }
    }

    if (!dev->bulk_out_endpointAddr &&
        ((endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_OUT) &&
        ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
         USB_ENDPOINT_XFER_BULK)) {
      /* we found a bulk out endpoint */
      dev->bulk_out_size = buffer_size;
      dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
      dev->bulk_out_buffer = kmalloc(buffer_size, GFP_KERNEL);
      if (!dev->bulk_out_buffer) {
        pr_err("Could not allocate bulk_in_buffer");
        goto error1;
      }

      dev->bulk_out_urb = usb_alloc_urb(0, GFP_KERNEL);
      if (!dev->bulk_out_urb) {
        retval = -ENOMEM;
        goto error3;
      }

      dev->MaxPacketSize = endpoint->wMaxPacketSize;
    }
  }
  if (!(dev->bulk_in_endpointAddr && dev->bulk_out_endpointAddr)) {
    pr_err("Could not find both bulk-in and bulk-out endpoints");
    goto error;
  }

  /* save our data pointer in this interface device */
  usb_set_intfdata(interface, dev);

  /* we can register the device now, as it is ready */
  retval = usb_register_dev(interface, &mini_class);
  if (retval) {
    /* something prevented us from registering this driver */
    pr_err("Not able to get a minor for this device.");
    usb_set_intfdata(interface, NULL);
    goto error;
  }
  /* let the user know what node this device is now attached to */
  printk("Piico MiniPCIe device now attached to PiicoMiNi%d\n",
         interface->minor);
  return 0;

error3:
  kfree(dev->bulk_out_buffer);
// error2:
//	usb_free_urb(dev->bulk_in_urb);
error1:
  kfree(dev->bulk_in_buffer);
error:
  if (dev) kref_put(&dev->kref, mini_delete);
  return retval;
}

static void mini_disconnect(struct usb_interface *interface) {
  struct piico_mini *dev;
  int minor = interface->minor;

  /* prevent skel_open() from racing skel_disconnect() */
  //	lock_kernel();

  dev = usb_get_intfdata(interface);
  usb_set_intfdata(interface, NULL);

  /* give back our minor */
  usb_deregister_dev(interface, &mini_class);

  //	unlock_kernel();

  /* decrement our usage count */
  kref_put(&dev->kref, mini_delete);

  printk("PiicoMiNi #%d now disconnected\n", minor);
}

static struct usb_driver mini_driver = {
    .name = "piico_mini",
    .probe = mini_probe,
    .disconnect = mini_disconnect,
    .id_table = mini_table,
};

static int __init piico_mini_init(void) {
  int result;

  /* register this driver with the USB subsystem */
  result = usb_register(&mini_driver);
  if (result) pr_err("usb_register failed. Error number %d", result);

  return result;
}

static void __exit piico_mini_exit(void) {
  /* deregister this driver with the USB subsystem */
  usb_deregister(&mini_driver);
}

module_init(piico_mini_init);
module_exit(piico_mini_exit);

MODULE_LICENSE("Dual BSD/GPL")

    ;
