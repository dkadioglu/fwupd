/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <tss2/tss2_esys.h>

#include "fu-common.h"

#include "fu-tpm-eventlog-common.h"
#include "fu-tpm-eventlog-device.h"

struct _FuTpmEventlogDevice {
	FuDevice		 parent_instance;
	GPtrArray		*items;
};

G_DEFINE_TYPE (FuTpmEventlogDevice, fu_tpm_eventlog_device, FU_TYPE_DEVICE)

typedef struct __attribute__ ((packed)) {
	guint32		 pcr_index;
	guint32		 event_type;
	guint8		 digest[TPM2_SHA1_DIGEST_SIZE];
	guint32		 event_data_sz;
} TpmPcrEvent;

typedef struct {
	FuTpmEventlogItemKind	 kind;
	gchar			*checksum;
	GBytes			*blob;
} FuTpmEventlogDeviceItem;

static gchar *
fu_tpm_eventlog_device_blobstr (GBytes *blob)
{
	GString *str = g_string_new (NULL);
	gsize bufsz = 0;
	const guint8 *buf = g_bytes_get_data (blob, &bufsz);
	for (gsize i = 0; i < bufsz; i++) {
		gchar chr = buf[i];
		if (g_ascii_isprint (chr))
			g_string_append_c (str, chr);
		else
			g_string_append_c (str, '.');
	}
	return g_string_free (str, FALSE);
}

static void
fu_tpm_eventlog_device_item_to_string (FuTpmEventlogDeviceItem *item, guint idt, GString *str)
{
	g_autofree gchar *blobstr = fu_tpm_eventlog_device_blobstr (item->blob);
	fu_common_string_append_kx (str, idt, "Type", item->kind);
	fu_common_string_append_kv (str, idt, "Description", fu_tpm_eventlog_item_kind_to_string (item->kind));
	fu_common_string_append_kv (str, idt, "Checksum", item->checksum);
	fu_common_string_append_kv (str, idt, "BlobStr", blobstr);
}

static void
fu_tpm_eventlog_device_to_string (FuDevice *device, guint idt, GString *str)
{
	FuTpmEventlogDevice *self = FU_TPM_EVENTLOG_DEVICE (device);
	if (self->items->len > 0) {
		fu_common_string_append_kv (str, idt, "Items", NULL);
		for (guint i = 0; i < self->items->len; i++) {
			FuTpmEventlogDeviceItem *item = g_ptr_array_index (self->items, i);
			fu_tpm_eventlog_device_item_to_string (item, idt + 1, str);
		}
	}
}

static void
fu_tpm_eventlog_device_item_free (FuTpmEventlogDeviceItem *item)
{
	g_bytes_unref (item->blob);
	g_free (item->checksum);
	g_free (item);
}

static void
fu_tpm_eventlog_device_init (FuTpmEventlogDevice *self)
{
	self->items = g_ptr_array_new_with_free_func ((GDestroyNotify) fu_tpm_eventlog_device_item_free);
	fu_device_set_name (FU_DEVICE (self), "Event Log");
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_set_logical_id (FU_DEVICE (self), "event-log");
	fu_device_add_instance_id (FU_DEVICE (self), "TpmPcrEvent");
}

static void
fu_tpm_eventlog_device_finalize (GObject *object)
{
	FuTpmEventlogDevice *self = FU_TPM_EVENTLOG_DEVICE (object);

	g_ptr_array_unref (self->items);

	G_OBJECT_CLASS (fu_tpm_eventlog_device_parent_class)->finalize (object);
}

static void
fu_tpm_eventlog_device_class_init (FuTpmEventlogDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	object_class->finalize = fu_tpm_eventlog_device_finalize;
	klass_device->to_string = fu_tpm_eventlog_device_to_string;
}

static gboolean
fu_tpm_eventlog_device_parse_blob (FuTpmEventlogDevice *self,
				   const guint8 *buf, gsize bufsz,
				   GError **error)
{
	for (gsize idx = 0; idx < bufsz; idx += sizeof(TpmPcrEvent)) {
		TpmPcrEvent evt;
		guint32 datasz;
		if (!fu_memcpy_safe ((guint8 *) &evt, sizeof(evt), 0x0,	/* dst */
				     buf, bufsz, idx, sizeof(evt),	/* src */
				     error))
			return FALSE;
		datasz = GUINT32_FROM_LE(evt.event_data_sz);
		if (evt.pcr_index == ESYS_TR_PCR0) {
			FuTpmEventlogDeviceItem *item;
			g_autofree guint8 *data = NULL;
			g_autoptr(GString) csum = g_string_new (NULL);

			/* build checksum */
			for (guint i = 0; i < 20; i++)
				g_string_append_printf (csum, "%02x", evt.digest[i]);

			/* build item */
			data = g_malloc0 (datasz);
			if (!fu_memcpy_safe (data, datasz, 0x0,	/* dst */
					     buf, bufsz, idx + sizeof(TpmPcrEvent), datasz,	/* src */
					     error))
				return FALSE;
			item = g_new0 (FuTpmEventlogDeviceItem, 1);
			item->kind = GUINT32_FROM_LE(evt.event_type);
			item->checksum = g_string_free (g_steal_pointer (&csum), FALSE);
			item->blob = g_bytes_new_take (g_steal_pointer (&data), datasz);
			g_ptr_array_add (self->items, item);

			/* not normally required */
			if (g_getenv ("FWUPD_TPM_EVENTLOG_VERBOSE") != NULL)
				fu_common_dump_bytes (G_LOG_DOMAIN, "Event Data", item->blob);
		}
		idx += datasz;
	}
	return TRUE;
}

FuDevice *
fu_tpm_eventlog_device_new (const guint8 *buf, gsize bufsz, GError **error)
{
	g_autoptr(FuTpmEventlogDevice) self = NULL;

	g_return_val_if_fail (buf != NULL, NULL);

	/* create object */
	self = g_object_new (FU_TYPE_TPM_EVENTLOG_DEVICE, NULL);
	if (!fu_tpm_eventlog_device_parse_blob (self, buf, bufsz, error))
		return NULL;
	return FU_DEVICE (g_steal_pointer (&self));
}
