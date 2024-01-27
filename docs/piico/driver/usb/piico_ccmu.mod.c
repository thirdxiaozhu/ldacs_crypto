#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xef31351c, "usb_alloc_urb" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xef07e8e1, "usb_free_urb" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xa6257a2f, "complete" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0x914ccc00, "usb_register_driver" },
	{ 0xcf2a6966, "up" },
	{ 0x37a0cba, "kfree" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x8b00e31, "usb_find_interface" },
	{ 0x122c3a7e, "_printk" },
	{ 0x7e668c8a, "usb_put_dev" },
	{ 0x8968d689, "usb_bulk_msg" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0xa0b2b155, "usb_get_dev" },
	{ 0x2e6c9f5a, "usb_submit_urb" },
	{ 0x40fe35a3, "usb_register_dev" },
	{ 0x21d81531, "usb_deregister" },
	{ 0x25974000, "wait_for_completion" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x8d4844b8, "usb_deregister_dev" },
	{ 0x6bd0e573, "down_interruptible" },
	{ 0x850e6a88, "kmalloc_trace" },
	{ 0xad6d045f, "kmalloc_caches" },
	{ 0x453e7dc, "module_layout" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("usb:v9118p2104d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v9118p2206d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v9118p2208d*dc*dsc*dp*ic*isc*ip*in*");

MODULE_INFO(srcversion, "3867987D83093B001CD8C36");
