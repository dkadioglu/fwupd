/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <tss2/tss2_esys.h>

#include "fu-tpm-device.h"
#include "fu-tpm-eventlog-device.h"

struct _FuTpmDevice {
	FuUdevDevice		 parent_instance;
};

G_DEFINE_TYPE (FuTpmDevice, fu_tpm_device, FU_TYPE_UDEV_DEVICE)

static void Esys_Finalize_autoptr_cleanup (ESYS_CONTEXT *esys_context)
{
	Esys_Finalize (&esys_context);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ESYS_CONTEXT, Esys_Finalize_autoptr_cleanup)

static gboolean
fu_tpm_device_probe (FuUdevDevice *device, GError **error)
{
	FuTpmDevice *self = FU_TPM_DEVICE (device);

	/* set the physical ID */
	if (!fu_udev_device_set_physical_id (device, "tpm", error))
		return FALSE;

	/* already open, so don't touch */
	g_object_set (self, "device-file", NULL, NULL);
	return TRUE;
}

static gboolean
fu_tpm_device_setup_event_log (FuTpmDevice *self, GError **error)
{
	gsize bufsz = 0;
	g_autofree gchar *basename = NULL;
	g_autofree gchar *fn = NULL;
	g_autofree guint8 *buf = NULL;
	g_autoptr(FuDevice) dev = NULL;

	basename = g_path_get_basename (fu_device_get_physical_id (FU_DEVICE (self)));
	fn = g_build_filename ("/sys/kernel/security", basename, "binary_bios_measurements", NULL);
	if (!g_file_get_contents (fn, (gchar **) &buf, &bufsz, error))
		return FALSE;
	if (bufsz == 0) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INVALID_FILE,
			     "failed to read data from %s", fn);
		return FALSE;
	}
	dev = fu_tpm_eventlog_device_new (buf, bufsz, error);
	if (dev == NULL)
		return FALSE;
	if (!fu_device_setup (dev, error))
		return FALSE;
	fu_device_add_child (FU_DEVICE (self), dev);
	return TRUE;
}

static gboolean
fu_plugin_tpm_get_uint32 (ESYS_CONTEXT *ctx, guint32 query, guint32 *val, GError **error)
{
	TSS2_RC rc;
	g_autofree TPMS_CAPABILITY_DATA *capability = NULL;

	g_return_val_if_fail (val != NULL, FALSE);

	rc = Esys_GetCapability (ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				 TPM2_CAP_TPM_PROPERTIES, query, 1, NULL, &capability);
	if (rc != TSS2_RC_SUCCESS) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			     "capability request failed for query %x", query);
		return FALSE;
	}
	if (capability->data.tpmProperties.count == 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			     "no properties returned for query %x", query);
		return FALSE;
	}
	if (capability->data.tpmProperties.tpmProperty[0].property != query) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			     "wrong query returned (got %x expected %x)",
			     capability->data.tpmProperties.tpmProperty[0].property,
			     query);
		return FALSE;
	}

	*val = GUINT32_FROM_BE (capability->data.tpmProperties.tpmProperty[0].value);
	return TRUE;
}

static gchar *
fu_plugin_tpm_get_string (ESYS_CONTEXT *ctx, guint32 query, GError **error)
{
	guint32 val = 0;
	gchar result[5] = {'\0'};

	/* return four bytes */
	if (!fu_plugin_tpm_get_uint32 (ctx, query, &val, error))
		return NULL;
	memcpy (result, (gchar *) &val, 4);

	/* convert non-ASCII into spaces */
	for (guint i = 0; i < 4; i++) {
		if (!g_ascii_isgraph (result[i]) && result[i] != '\0')
			result[i] = 0x20;
	}

	return fu_common_strstrip (result);
}

static const gchar *
fu_tpm_device_convert_manufacturer (const gchar *manufacturer)
{
	if (g_strcmp0 (manufacturer, "AMD") == 0)
		return "AMD";
	if (g_strcmp0 (manufacturer, "ATML") == 0)
		return "Atmel";
	if (g_strcmp0 (manufacturer, "BRCM") == 0)
		return "Broadcom";
	if (g_strcmp0 (manufacturer, "IBM") == 0)
		return "IBM";
	if (g_strcmp0 (manufacturer, "IFX") == 0)
		return "Infineon";
	if (g_strcmp0 (manufacturer, "INTC") == 0)
		return "Intel";
	if (g_strcmp0 (manufacturer, "LEN") == 0)
		return "Lenovo";
	if (g_strcmp0 (manufacturer, "NSM") == 0)
		return "National Semiconductor";
	if (g_strcmp0 (manufacturer, "NTZ") == 0)
		return "Nationz";
	if (g_strcmp0 (manufacturer, "NTC") == 0)
		return "Nuvoton Technology";
	if (g_strcmp0 (manufacturer, "QCOM") == 0)
		return "Qualcomm";
	if (g_strcmp0 (manufacturer, "SMSC") == 0)
		return "SMSC";
	if (g_strcmp0 (manufacturer, "STM") == 0)
		return "ST Microelectronics";
	if (g_strcmp0 (manufacturer, "SMSN") == 0)
		return "Samsung";
	if (g_strcmp0 (manufacturer, "SNS") == 0)
		return "Sinosun";
	if (g_strcmp0 (manufacturer, "TXN") == 0)
		return "Texas Instruments";
	if (g_strcmp0 (manufacturer, "WEC") == 0)
		return "Winbond";
	if (g_strcmp0 (manufacturer, "ROCC") == 0)
		return "Fuzhou Rockchip";
	return NULL;
}

static gboolean
fu_tpm_device_setup (FuDevice *device, GError **error)
{
	FuTpmDevice *self = FU_TPM_DEVICE (device);
	FwupdVersionFormat verfmt;
	TSS2_RC rc;
	const gchar *tmp;
	guint32 tpm_type = 0;
	guint32 version1 = 0;
	guint32 version2 = 0;
	guint64 version_raw;
	g_autofree gchar *family = NULL;
	g_autofree gchar *id1 = NULL;
	g_autofree gchar *id2 = NULL;
	g_autofree gchar *id3 = NULL;
	g_autofree gchar *id4 = NULL;
	g_autofree gchar *manufacturer = NULL;
	g_autofree gchar *model1 = NULL;
	g_autofree gchar *model2 = NULL;
	g_autofree gchar *model3 = NULL;
	g_autofree gchar *model4 = NULL;
	g_autofree gchar *model = NULL;
	g_autofree gchar *vendor_id = NULL;
	g_autofree gchar *version = NULL;
	g_autoptr(ESYS_CONTEXT) ctx = NULL;
	g_autoptr(GError) error_local = NULL;

	/* setup TSS */
	rc = Esys_Initialize (&ctx, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		g_set_error_literal (error, FWUPD_ERROR, FWUPD_ERROR_NOT_FOUND,
				     "failed to initialize TPM library");
		return FALSE;
	}
	rc = Esys_Startup (ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
				     "failed to initialize TPM");
		return FALSE;
	}

	/* lookup guaranteed details from TPM */
	family = fu_plugin_tpm_get_string (ctx, TPM2_PT_FAMILY_INDICATOR, error);
	if (family == NULL) {
		g_prefix_error (error, "failed to read TPM family");
		return FALSE;
	}
	manufacturer = fu_plugin_tpm_get_string (ctx, TPM2_PT_MANUFACTURER, error);
	if (manufacturer == NULL) {
		g_prefix_error (error, "failed to read TPM manufacturer");
		return FALSE;
	}
	model1 = fu_plugin_tpm_get_string (ctx, TPM2_PT_VENDOR_STRING_1, error);
	if (model1 == NULL) {
		g_prefix_error (error, "failed to read TPM vendor string");
		return FALSE;
	}
	if (!fu_plugin_tpm_get_uint32 (ctx, TPM2_PT_VENDOR_TPM_TYPE, &tpm_type, error)) {
		g_prefix_error (error, "failed to read TPM type");
		return FALSE;
	}

	/* these are not guaranteed by spec and may be NULL */
	model2 = fu_plugin_tpm_get_string (ctx, TPM2_PT_VENDOR_STRING_2, error);
	model3 = fu_plugin_tpm_get_string (ctx, TPM2_PT_VENDOR_STRING_3, error);
	model4 = fu_plugin_tpm_get_string (ctx, TPM2_PT_VENDOR_STRING_4, error);
	model = g_strjoin ("", model1, model2, model3, model4, NULL);

	/* add GUIDs to daemon */
	id1 = g_strdup_printf ("TPM\\VEN_%s&DEV_%04X", manufacturer, tpm_type);
	fu_device_add_instance_id (device, id1);
	id2 = g_strdup_printf ("TPM\\VEN_%s&MOD_%s", manufacturer, model);
	fu_device_add_instance_id (device, id2);
	id3 = g_strdup_printf ("TPM\\VEN_%s&DEV_%04X&VER_%s", manufacturer, tpm_type, family);
	fu_device_add_instance_id (device, id3);
	id4 = g_strdup_printf ("TPM\\VEN_%s&MOD_%s&VER_%s", manufacturer, model, family);
	fu_device_add_instance_id (device, id4);

	/* enforce vendors can only ship updates for thier own hardware */
	vendor_id = g_strdup_printf ("TPM:%s", manufacturer);
	fu_device_set_vendor_id (device, vendor_id);
	tmp = fu_tpm_device_convert_manufacturer (manufacturer);
	fu_device_set_vendor (device, tmp != NULL ? tmp : manufacturer);

	/* get version */
	if (!fu_plugin_tpm_get_uint32 (ctx, TPM2_PT_FIRMWARE_VERSION_1, &version1, error))
		return FALSE;
	if (!fu_plugin_tpm_get_uint32 (ctx, TPM2_PT_FIRMWARE_VERSION_2, &version2, error))
		return FALSE;
	version_raw = ((guint64) version1) << 32 | ((guint64) version2);
	fu_device_set_version_raw (device, version_raw);

	/* this has to be done after _add_instance_id() adds the quirks */
	verfmt = fu_device_get_version_format (device);
	version = fu_common_version_from_uint64 (version_raw, verfmt);
	fu_device_set_version (device, version, verfmt);

	/* try to add the event log as a child */
	if (!fu_tpm_device_setup_event_log (self, &error_local))
		g_warning ("no event log: %s", error_local->message);

	/* success */
	return TRUE;
}

static void
fu_tpm_device_init (FuTpmDevice *self)
{
	fu_device_set_name (FU_DEVICE (self), "TPM");
	fu_device_set_version_format (FU_DEVICE (self), FWUPD_VERSION_FORMAT_QUAD);
	fu_udev_device_set_readonly (FU_UDEV_DEVICE (self), TRUE);
}

static void
fu_tpm_device_finalize (GObject *object)
{
	G_OBJECT_CLASS (fu_tpm_device_parent_class)->finalize (object);
}

static void
fu_tpm_device_class_init (FuTpmDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	FuUdevDeviceClass *klass_udev_device = FU_UDEV_DEVICE_CLASS (klass);
	object_class->finalize = fu_tpm_device_finalize;
	klass_device->setup = fu_tpm_device_setup;
	klass_udev_device->probe = fu_tpm_device_probe;
}
