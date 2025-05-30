#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

variable "options" {
  type        = any
  description = "module options of the CML deployment as an object"
}

variable "cfg" {
  type        = any
  description = "Processed configuration object for the CML deployment"
}
