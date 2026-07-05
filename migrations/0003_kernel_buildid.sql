-- SPDX-License-Identifier: GPL-2.0-only
-- GNU build-id of the reporting device's running kernel (optional,
-- from /sys/kernel/notes); used to validate fetched debug symbols.

ALTER TABLE report ADD COLUMN kernel_buildid TEXT;
